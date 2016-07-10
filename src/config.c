/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "wireguard.h"
#include "config.h"
#include "device.h"
#include "socket.h"
#include "packets.h"
#include "timers.h"
#include "hashtables.h"
#include "peer.h"
#include "uapi.h"

static int set_peer_dst(struct wireguard_peer *peer, void *data)
{
	socket_set_peer_dst(peer);
	return 0;
}

static int set_device_port(struct wireguard_device *wg, u16 port)
{
	if (!port)
		return -EINVAL;
	socket_uninit(wg);
	wg->incoming_port = port;
	if (netdev_pub(wg)->flags & IFF_UP) {
		peer_for_each_unlocked(wg, set_peer_dst, NULL);
		return socket_init(wg);
	}
	return 0;
}

static int set_ipmask(struct wireguard_peer *peer, void __user *user_ipmask)
{
	int ret = 0;
	struct wgipmask in_ipmask;

	ret = copy_from_user(&in_ipmask, user_ipmask, sizeof(in_ipmask));
	if (ret) {
		ret = -EFAULT;
		return ret;
	}

	if (in_ipmask.family == AF_INET && in_ipmask.cidr <= 32)
		ret = routing_table_insert_v4(&peer->device->peer_routing_table, &in_ipmask.ip4, in_ipmask.cidr, peer);
	else if (in_ipmask.family == AF_INET6 && in_ipmask.cidr <= 128)
		ret = routing_table_insert_v6(&peer->device->peer_routing_table, &in_ipmask.ip6, in_ipmask.cidr, peer);

	return ret;
}

static const uint8_t zeros[WG_KEY_LEN] = { 0 };

static int set_peer(struct wireguard_device *wg, void __user *user_peer, size_t *len)
{
	int ret = 0;
	size_t i;
	struct wgpeer in_peer;
	void __user *user_ipmask;
	struct wireguard_peer *peer = NULL;

	ret = copy_from_user(&in_peer, user_peer, sizeof(in_peer));
	if (ret) {
		ret = -EFAULT;
		return ret;
	}

	if (!memcmp(zeros, in_peer.public_key, NOISE_PUBLIC_KEY_LEN))
		return -EINVAL; /* Can't add a peer with no public key. */

	peer = pubkey_hashtable_lookup(&wg->peer_hashtable, in_peer.public_key);
	if (!peer) { /* Peer doesn't exist yet. Add a new one. */
		if (in_peer.remove_me)
			return -ENODEV; /* Tried to remove a non existing peer. */
		peer = peer_create(wg, in_peer.public_key);
		if (!peer)
			return -ENOMEM;
		rcu_read_lock();
		peer = peer_get(peer);
		rcu_read_unlock();
		if (!peer) {
			pr_err("Peer disappeared while creating\n");
			return -EAGAIN;
		}
		if (netdev_pub(wg)->flags & IFF_UP)
			timers_init_peer(peer);
	} else
		pr_debug("Peer %Lu (%pISpfsc) modified\n", peer->internal_id, &peer->endpoint_addr);

	if (in_peer.remove_me) {
		peer_put(peer);
		peer_remove(peer);
		return 0;
	}

	if (in_peer.endpoint.ss_family == AF_INET || in_peer.endpoint.ss_family == AF_INET6)
		socket_set_peer_addr(peer, &in_peer.endpoint);

	if (in_peer.replace_ipmasks)
		routing_table_remove_by_peer(&wg->peer_routing_table, peer);
	for (i = 0, user_ipmask = user_peer + sizeof(struct wgpeer); i < in_peer.num_ipmasks; ++i, user_ipmask += sizeof(struct wgipmask)) {
		ret = set_ipmask(peer, user_ipmask);
		if (ret)
			break;
	}

	if (in_peer.persistent_keepalive_interval != (uint16_t)-1) {
		if (in_peer.persistent_keepalive_interval && (in_peer.persistent_keepalive_interval < 10 || in_peer.persistent_keepalive_interval > 3600))
			ret = -EINVAL;
		else {
			if (in_peer.persistent_keepalive_interval && netdev_pub(wg)->flags & IFF_UP) {
				if (!peer->persistent_keepalive_interval)
					packet_send_keepalive(peer);
				set_timer_slack(&peer->timer_persistent_keepalive, max_t(int, HZ / 2, (unsigned long)in_peer.persistent_keepalive_interval * HZ / 256));
			}
			peer->persistent_keepalive_interval = (unsigned long)in_peer.persistent_keepalive_interval * HZ;
		}
	}

	if (netdev_pub(wg)->flags & IFF_UP)
		packet_send_queue(peer);

	peer_put(peer);

	if (!ret)
		*len = sizeof(struct wgpeer) + (in_peer.num_ipmasks * sizeof(struct wgipmask));

	return ret;
}

int config_set_device(struct wireguard_device *wg, void __user *user_device)
{
	int ret = 0;
	size_t i, offset;
	struct wgdevice in_device;
	void __user *user_peer;

	BUILD_BUG_ON(WG_KEY_LEN != NOISE_PUBLIC_KEY_LEN);
	BUILD_BUG_ON(WG_KEY_LEN != NOISE_SYMMETRIC_KEY_LEN);

	mutex_lock(&wg->device_update_lock);

	ret = copy_from_user(&in_device, user_device, sizeof(in_device));
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	if (in_device.port) {
		ret = set_device_port(wg, in_device.port);
		if (ret)
			goto out;
	}

	if (in_device.replace_peer_list)
		peer_remove_all(wg);

	if (in_device.remove_private_key)
		noise_set_static_identity_private_key(&wg->static_identity, NULL);
	else if (memcmp(zeros, in_device.private_key, WG_KEY_LEN))
		noise_set_static_identity_private_key(&wg->static_identity, in_device.private_key);

	if (in_device.remove_preshared_key)
		noise_set_static_identity_preshared_key(&wg->static_identity, NULL);
	else if (memcmp(zeros, in_device.preshared_key, WG_KEY_LEN))
		noise_set_static_identity_preshared_key(&wg->static_identity, in_device.preshared_key);

	for (i = 0, offset = 0, user_peer = user_device + sizeof(struct wgdevice); i < in_device.num_peers; ++i, user_peer += offset) {
		ret = set_peer(wg, user_peer, &offset);
		if (ret)
			break;
	}

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

static int calculate_ipmasks_size(void *ctx, struct wireguard_peer *peer, union nf_inet_addr ip, uint8_t cidr, int family)
{
	size_t *count = ctx;
	*count += sizeof(struct wgipmask);
	return 0;
}

static size_t calculate_peers_size(struct wireguard_device *wg)
{
	size_t len = peer_total_count(wg) * sizeof(struct wgpeer);
	routing_table_walk_ips(&wg->peer_routing_table, &len, calculate_ipmasks_size);
	return len;
}

static int populate_ipmask(void *ctx, union nf_inet_addr ip, uint8_t cidr, int family)
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

	ret = copy_to_user(uipmask, &out_ipmask, sizeof(out_ipmask));
	if (ret)
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
	out_peer.endpoint = peer->endpoint_addr;
	read_unlock_bh(&peer->endpoint_lock);
	out_peer.last_handshake_time = peer->walltime_last_handshake;
	out_peer.tx_bytes = peer->tx_bytes;
	out_peer.rx_bytes = peer->rx_bytes;
	out_peer.persistent_keepalive_interval = (uint16_t)(peer->persistent_keepalive_interval / HZ);

	ipmasks_data.out_len = data->out_len;
	ipmasks_data.data = data->data;
	ret = routing_table_walk_ips_by_peer_sleepable(&peer->device->peer_routing_table, &ipmasks_data, peer, populate_ipmask);
	if (ret)
		return ret;
	data->out_len = ipmasks_data.out_len;
	data->data = ipmasks_data.data;
	out_peer.num_ipmasks = ipmasks_data.count;

	ret = copy_to_user(upeer, &out_peer, sizeof(out_peer));
	if (ret)
		ret = -EFAULT;
	return ret;
}


int config_get_device(struct wireguard_device *wg, void __user *udevice)
{
	int ret = 0;
	struct net_device *dev = netdev_pub(wg);
	struct data_remaining peer_data = { NULL };
	struct wgdevice out_device;
	struct wgdevice in_device;

	BUILD_BUG_ON(WG_KEY_LEN != NOISE_PUBLIC_KEY_LEN);
	BUILD_BUG_ON(WG_KEY_LEN != NOISE_SYMMETRIC_KEY_LEN);

	memset(&out_device, 0, sizeof(struct wgdevice));

	mutex_lock(&wg->device_update_lock);

	if (!udevice) {
		ret = calculate_peers_size(wg);
		goto out;
	}

	ret = copy_from_user(&in_device, udevice, sizeof(in_device));
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	out_device.port = wg->incoming_port;
	strncpy(out_device.interface, dev->name, IFNAMSIZ - 1);
	out_device.interface[IFNAMSIZ - 1] = 0;

	down_read(&wg->static_identity.lock);
	if (wg->static_identity.has_identity) {
		memcpy(out_device.private_key, wg->static_identity.static_private, WG_KEY_LEN);
		memcpy(out_device.public_key, wg->static_identity.static_public, WG_KEY_LEN);
		memcpy(out_device.preshared_key, wg->static_identity.preshared_key, WG_KEY_LEN);
	}
	up_read(&wg->static_identity.lock);

	peer_data.out_len = in_device.peers_size;
	peer_data.data = udevice + sizeof(struct wgdevice);
	ret = peer_for_each_unlocked(wg, populate_peer, &peer_data);
	if (ret)
		goto out;
	out_device.num_peers = peer_data.count;

	ret = copy_to_user(udevice, &out_device, sizeof(out_device));
	if (ret)
		ret = -EFAULT;

out:
	mutex_unlock(&wg->device_update_lock);
	memzero_explicit(&out_device.private_key, NOISE_PUBLIC_KEY_LEN);
	return ret;
}
