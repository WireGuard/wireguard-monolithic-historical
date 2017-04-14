/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "config.h"
#include "device.h"
#include "socket.h"
#include "packets.h"
#include "timers.h"
#include "hashtables.h"
#include "peer.h"
#include "uapi.h"

static int clear_peer_endpoint_src(struct wireguard_peer *peer, void *data)
{
	socket_clear_peer_endpoint_src(peer);
	return 0;
}

static int set_device_port(struct wireguard_device *wg, u16 port)
{
	socket_uninit(wg);
	wg->incoming_port = port;
	if (!(netdev_pub(wg)->flags & IFF_UP))
		return 0;
	peer_for_each_unlocked(wg, clear_peer_endpoint_src, NULL);
	return socket_init(wg);
}

static int set_ipmask(struct wireguard_peer *peer, void __user *user_ipmask)
{
	int ret = -EINVAL;
	struct wgipmask in_ipmask;

	if (copy_from_user(&in_ipmask, user_ipmask, sizeof(in_ipmask)))
		return -EFAULT;

	if (in_ipmask.family == AF_INET && in_ipmask.cidr <= 32)
		ret = routing_table_insert_v4(&peer->device->peer_routing_table, &in_ipmask.ip4, in_ipmask.cidr, peer);
	else if (in_ipmask.family == AF_INET6 && in_ipmask.cidr <= 128)
		ret = routing_table_insert_v6(&peer->device->peer_routing_table, &in_ipmask.ip6, in_ipmask.cidr, peer);

	return ret;
}

static const u8 zeros[WG_KEY_LEN] = { 0 };

static int set_peer(struct wireguard_device *wg, void __user *user_peer, size_t *len)
{
	int ret = 0;
	size_t i;
	struct wgpeer in_peer;
	void __user *user_ipmask;
	struct wireguard_peer *peer = NULL;

	if (copy_from_user(&in_peer, user_peer, sizeof(in_peer)))
		return -EFAULT;

	if (!memcmp(zeros, in_peer.public_key, NOISE_PUBLIC_KEY_LEN))
		return -EINVAL; /* Can't add a peer with no public key. */

	peer = pubkey_hashtable_lookup(&wg->peer_hashtable, in_peer.public_key);
	if (!peer) { /* Peer doesn't exist yet. Add a new one. */
		if (in_peer.flags & WGPEER_REMOVE_ME)
			return -ENODEV; /* Tried to remove a non existing peer. */

		down_read(&wg->static_identity.lock);
		if (wg->static_identity.has_identity && !memcmp(in_peer.public_key, wg->static_identity.static_public, NOISE_PUBLIC_KEY_LEN)) {
			/* We silently ignore peers that have the same public key as the device. The reason we do it silently
			 * is that we'd like for people to be able to reuse the same set of API calls across peers. */
			up_read(&wg->static_identity.lock);
			goto out;
		}
		up_read(&wg->static_identity.lock);

		peer = peer_rcu_get(peer_create(wg, in_peer.public_key));
		if (!peer)
			return -ENOMEM;
		if (netdev_pub(wg)->flags & IFF_UP)
			timers_init_peer(peer);
	}

	if (in_peer.flags & WGPEER_REMOVE_ME) {
		peer_put(peer);
		peer_remove(peer);
		goto out;
	}

	if (in_peer.endpoint.addr.sa_family == AF_INET || in_peer.endpoint.addr.sa_family == AF_INET6) {
		struct endpoint endpoint = { { { 0 } } };
		memcpy(&endpoint, &in_peer.endpoint, sizeof(in_peer.endpoint));
		socket_set_peer_endpoint(peer, &endpoint);
	}

	if (in_peer.flags & WGPEER_REPLACE_IPMASKS)
		routing_table_remove_by_peer(&wg->peer_routing_table, peer);
	for (i = 0, user_ipmask = user_peer + sizeof(struct wgpeer); i < in_peer.num_ipmasks; ++i, user_ipmask += sizeof(struct wgipmask)) {
		ret = set_ipmask(peer, user_ipmask);
		if (ret)
			break;
	}

	if (in_peer.persistent_keepalive_interval != (u16)-1) {
		const bool send_keepalive = !peer->persistent_keepalive_interval && in_peer.persistent_keepalive_interval && netdev_pub(wg)->flags & IFF_UP;
		peer->persistent_keepalive_interval = (unsigned long)in_peer.persistent_keepalive_interval * HZ;
		if (send_keepalive)
			packet_send_keepalive(peer);
	}

	if (netdev_pub(wg)->flags & IFF_UP)
		packet_send_queue(peer);

	peer_put(peer);

out:
	if (!ret)
		*len = sizeof(struct wgpeer) + (in_peer.num_ipmasks * sizeof(struct wgipmask));

	return ret;
}

int config_set_device(struct wireguard_device *wg, void __user *user_device)
{
	int ret;
	size_t i, offset;
	struct wgdevice in_device;
	void __user *user_peer;
	bool modified_static_identity = false;

	BUILD_BUG_ON(WG_KEY_LEN != NOISE_PUBLIC_KEY_LEN);
	BUILD_BUG_ON(WG_KEY_LEN != NOISE_SYMMETRIC_KEY_LEN);

	mutex_lock(&wg->device_update_lock);

	ret = -EFAULT;
	if (copy_from_user(&in_device, user_device, sizeof(in_device)))
		goto out;

	ret = -EPROTO;
	if (in_device.version_magic != WG_API_VERSION_MAGIC)
		goto out;

	if (in_device.fwmark || (!in_device.fwmark && (in_device.flags & WGDEVICE_REMOVE_FWMARK))) {
		wg->fwmark = in_device.fwmark;
		peer_for_each_unlocked(wg, clear_peer_endpoint_src, NULL);
	}

	if (in_device.port) {
		ret = set_device_port(wg, in_device.port);
		if (ret)
			goto out;
	}

	if (in_device.flags & WGDEVICE_REPLACE_PEERS)
		peer_remove_all(wg);

	if (in_device.flags & WGDEVICE_REMOVE_PRIVATE_KEY) {
		noise_set_static_identity_private_key(&wg->static_identity, NULL);
		modified_static_identity = true;
	} else if (memcmp(zeros, in_device.private_key, WG_KEY_LEN)) {
		u8 public_key[NOISE_PUBLIC_KEY_LEN] = { 0 };
		struct wireguard_peer *peer;
		/* We remove before setting, to prevent race, which means doing two 25519-genpub ops. */
		bool unused __attribute((unused)) = curve25519_generate_public(public_key, in_device.private_key);
		peer = pubkey_hashtable_lookup(&wg->peer_hashtable, public_key);
		if (peer) {
			peer_put(peer);
			peer_remove(peer);
		}

		noise_set_static_identity_private_key(&wg->static_identity, in_device.private_key);
		modified_static_identity = true;
	}

	if (in_device.flags & WGDEVICE_REMOVE_PRESHARED_KEY) {
		noise_set_static_identity_preshared_key(&wg->static_identity, NULL);
		modified_static_identity = true;
	} else if (memcmp(zeros, in_device.preshared_key, WG_KEY_LEN)) {
		noise_set_static_identity_preshared_key(&wg->static_identity, in_device.preshared_key);
		modified_static_identity = true;
	}

	if (modified_static_identity)
		cookie_checker_precompute_keys(&wg->cookie_checker, NULL);

	for (i = 0, offset = 0, user_peer = user_device + sizeof(struct wgdevice); i < in_device.num_peers; ++i, user_peer += offset) {
		ret = set_peer(wg, user_peer, &offset);
		if (ret)
			goto out;
	}
	ret = 0;
out:
	mutex_unlock(&wg->device_update_lock);
	memzero_explicit(&in_device.private_key, NOISE_PUBLIC_KEY_LEN);
	return ret;
}

struct data_remaining {
	void __user *data;
	size_t out_len;
	size_t count;
};

static inline int use_data(struct data_remaining *data, size_t size)
{
	if (data->out_len < size)
		return -EMSGSIZE;
	data->out_len -= size;
	data->data += size;
	++data->count;
	return 0;
}

static int populate_ipmask(void *ctx, union nf_inet_addr ip, u8 cidr, int family)
{
	int ret;
	struct data_remaining *data = ctx;
	void __user *uipmask = data->data;
	struct wgipmask out_ipmask;

	memset(&out_ipmask, 0, sizeof(struct wgipmask));

	ret = use_data(data, sizeof(struct wgipmask));
	if (ret)
		return ret;

	out_ipmask.cidr = cidr;
	out_ipmask.family = family;
	if (family == AF_INET)
		out_ipmask.ip4 = ip.in;
	else if (family == AF_INET6)
		out_ipmask.ip6 = ip.in6;

	if (copy_to_user(uipmask, &out_ipmask, sizeof(out_ipmask)))
		ret = -EFAULT;

	return ret;
}

static int populate_peer(struct wireguard_peer *peer, void *ctx)
{
	int ret = 0;
	struct data_remaining *data = ctx;
	void __user *upeer = data->data;
	struct wgpeer out_peer;
	struct data_remaining ipmasks_data = { NULL };

	memset(&out_peer, 0, sizeof(struct wgpeer));

	ret = use_data(data, sizeof(struct wgpeer));
	if (ret)
		return ret;

	memcpy(out_peer.public_key, peer->handshake.remote_static, NOISE_PUBLIC_KEY_LEN);
	read_lock_bh(&peer->endpoint_lock);
	if (peer->endpoint.addr.sa_family == AF_INET)
		out_peer.endpoint.addr4 = peer->endpoint.addr4;
	else if (peer->endpoint.addr.sa_family == AF_INET6)
		out_peer.endpoint.addr6 = peer->endpoint.addr6;
	read_unlock_bh(&peer->endpoint_lock);
	out_peer.last_handshake_time = peer->walltime_last_handshake;
	out_peer.tx_bytes = peer->tx_bytes;
	out_peer.rx_bytes = peer->rx_bytes;
	out_peer.persistent_keepalive_interval = (u16)(peer->persistent_keepalive_interval / HZ);

	ipmasks_data.out_len = data->out_len;
	ipmasks_data.data = data->data;
	ret = routing_table_walk_ips_by_peer_sleepable(&peer->device->peer_routing_table, &ipmasks_data, peer, populate_ipmask);
	if (ret)
		return ret;
	data->out_len = ipmasks_data.out_len;
	data->data = ipmasks_data.data;
	out_peer.num_ipmasks = ipmasks_data.count;

	if (copy_to_user(upeer, &out_peer, sizeof(out_peer)))
		ret = -EFAULT;
	return ret;
}

int config_get_device(struct wireguard_device *wg, void __user *user_device)
{
	int ret;
	struct net_device *dev = netdev_pub(wg);
	struct data_remaining peer_data = { NULL };
	struct wgdevice out_device;
	struct wgdevice in_device;

	BUILD_BUG_ON(WG_KEY_LEN != NOISE_PUBLIC_KEY_LEN);
	BUILD_BUG_ON(WG_KEY_LEN != NOISE_SYMMETRIC_KEY_LEN);

	memset(&out_device, 0, sizeof(struct wgdevice));

	mutex_lock(&wg->device_update_lock);

	if (!user_device) {
		ret = peer_total_count(wg) * sizeof(struct wgpeer)
		    + routing_table_count_nodes(&wg->peer_routing_table) * sizeof(struct wgipmask);
		goto out;
	}

	ret = -EFAULT;
	if (copy_from_user(&in_device, user_device, sizeof(in_device)))
		goto out;

	ret = -EPROTO;
	if (in_device.version_magic != WG_API_VERSION_MAGIC)
		goto out;

	out_device.version_magic = WG_API_VERSION_MAGIC;
	out_device.port = wg->incoming_port;
	out_device.fwmark = wg->fwmark;
	strncpy(out_device.interface, dev->name, IFNAMSIZ - 1);
	out_device.interface[IFNAMSIZ - 1] = 0;

	down_read(&wg->static_identity.lock);
	if (wg->static_identity.has_identity) {
		memcpy(out_device.private_key, wg->static_identity.static_private, WG_KEY_LEN);
		memcpy(out_device.public_key, wg->static_identity.static_public, WG_KEY_LEN);
	}
	if (wg->static_identity.has_psk)
		memcpy(out_device.preshared_key, wg->static_identity.preshared_key, WG_KEY_LEN);
	up_read(&wg->static_identity.lock);

	peer_data.out_len = in_device.peers_size;
	peer_data.data = user_device + sizeof(struct wgdevice);
	ret = peer_for_each_unlocked(wg, populate_peer, &peer_data);
	if (ret)
		goto out;
	out_device.num_peers = peer_data.count;

	ret = -EFAULT;
	if (copy_to_user(user_device, &out_device, sizeof(out_device)))
		goto out;

	ret = 0;

out:
	mutex_unlock(&wg->device_update_lock);
	memzero_explicit(&out_device.private_key, NOISE_PUBLIC_KEY_LEN);
	return ret;
}
