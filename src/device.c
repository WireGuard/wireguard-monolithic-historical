/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "packets.h"
#include "socket.h"
#include "timers.h"
#include "device.h"
#include "config.h"
#include "peer.h"
#include "uapi.h"
#include "messages.h"

#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/suspend.h>
#include <net/icmp.h>
#include <net/rtnetlink.h>
#include <net/ip_tunnels.h>
#include <net/addrconf.h>
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat_core.h>
#endif

static int open_peer(struct wireguard_peer *peer, void *data)
{
	timers_init_peer(peer);
	packet_send_queue(peer);
	if (peer->persistent_keepalive_interval)
		packet_send_keepalive(peer);
	return 0;
}

static int open(struct net_device *dev)
{
	int ret;
	struct wireguard_device *wg = netdev_priv(dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	struct inet6_dev *dev_v6 = __in6_dev_get(dev);
#endif
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);

	if (dev_v4) {
		/* TODO: when we merge to mainline, put this check near the ip_rt_send_redirect
		 * call of ip_forward in net/ipv4/ip_forward.c, similar to the current secpath
		 * check, rather than turning it off like this. This is just a stop gap solution
		 * while we're an out of tree module. */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	if (dev_v6)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
		dev_v6->addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#else
		dev_v6->cnf.addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#endif
#endif

	ret = socket_init(wg);
	if (ret < 0)
		return ret;
	peer_for_each(wg, open_peer, NULL);
	return 0;
}

static int clear_noise_peer(struct wireguard_peer *peer, void *data)
{
	noise_handshake_clear(&peer->handshake);
	noise_keypairs_clear(&peer->keypairs);
	if (peer->timers_enabled)
		del_timer(&peer->timer_kill_ephemerals);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int suspending_clear_noise_peers(struct notifier_block *nb, unsigned long action, void *data)
{
	struct wireguard_device *wg = container_of(nb, struct wireguard_device, clear_peers_on_suspend);
	if (action == PM_HIBERNATION_PREPARE || action == PM_SUSPEND_PREPARE) {
		peer_for_each(wg, clear_noise_peer, NULL);
		rcu_barrier_bh();
	}
	return 0;
}
#endif

static int stop_peer(struct wireguard_peer *peer, void *data)
{
	timers_uninit_peer(peer);
	clear_noise_peer(peer, data);
	return 0;
}

static int stop(struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	peer_for_each(wg, stop_peer, NULL);
	skb_queue_purge(&wg->incoming_handshakes);
	socket_uninit(wg);
	return 0;
}

static void skb_unsendable(struct sk_buff *skb, struct net_device *dev)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	/* This conntrack stuff is because the rate limiting needs to be applied
	 * to the original src IP, so we have to restore saddr in the IP header.
	 * It's not needed if conntracking isn't in the kernel, because in that
	 * case the saddr wouldn't be NAT-transformed anyway. */
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
#endif
	++dev->stats.tx_errors;

	if (skb->len >= sizeof(struct iphdr) && ip_hdr(skb)->version == 4) {
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
		if (ct)
			ip_hdr(skb)->saddr = ct->tuplehash[0].tuple.src.u3.ip;
#endif
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	} else if (skb->len >= sizeof(struct ipv6hdr) && ip_hdr(skb)->version == 6) {
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
		if (ct)
			ipv6_hdr(skb)->saddr = ct->tuplehash[0].tuple.src.u3.in6;
#endif
		icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
	}
	kfree_skb(skb);
}

static netdev_tx_t xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	struct wireguard_peer *peer;
	int ret;

	if (unlikely(dev_recursion_level() > 4)) {
		ret = -ELOOP;
		net_dbg_ratelimited("Routing loop detected\n");
		skb_unsendable(skb, dev);
		goto err;
	}

	peer = routing_table_lookup_dst(&wg->peer_routing_table, skb);
	if (unlikely(!peer)) {
		ret = -ENOKEY;
		net_dbg_skb_ratelimited("No peer is configured for %pISc\n", skb);
		goto err;
	}

	read_lock_bh(&peer->endpoint_lock);
	ret = peer->endpoint.addr.sa_family != AF_INET && peer->endpoint.addr.sa_family != AF_INET6;
	read_unlock_bh(&peer->endpoint_lock);
	if (unlikely(ret)) {
		ret = -EHOSTUNREACH;
		net_dbg_ratelimited("No valid endpoint has been configured or discovered for peer %Lu\n", peer->internal_id);
		goto err_peer;
	}

	/* If the queue is getting too big, we start removing the oldest packets until it's small again.
	 * We do this before adding the new packet, so we don't remove GSO segments that are in excess. */
	while (skb_queue_len(&peer->tx_packet_queue) > MAX_QUEUED_OUTGOING_PACKETS)
		dev_kfree_skb(skb_dequeue(&peer->tx_packet_queue));

	if (!skb_is_gso(skb))
		skb->next = NULL;
	else {
		struct sk_buff *segs = skb_gso_segment(skb, 0);
		if (unlikely(IS_ERR(segs))) {
			ret = PTR_ERR(segs);
			goto err_peer;
		}
		dev_kfree_skb(skb);
		skb = segs;
	}
	while (skb) {
		struct sk_buff *next = skb->next;
		skb->next = skb->prev = NULL;

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb))
			continue;

		/* We only need to keep the original dst around for icmp,
		 * so at this point we're in a position to drop it. */
		skb_dst_drop(skb);

		skb_queue_tail(&peer->tx_packet_queue, skb);
		skb = next;
	}

	packet_send_queue(peer);
	peer_put(peer);
	return NETDEV_TX_OK;

err_peer:
	peer_put(peer);
err:
	skb_unsendable(skb, dev);
	return ret;
}


static int ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct wireguard_device *wg = netdev_priv(dev);

	if (!ns_capable(dev_net(dev)->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case WG_GET_DEVICE:
		return config_get_device(wg, ifr->ifr_ifru.ifru_data);
	case WG_SET_DEVICE:
		return config_set_device(wg, ifr->ifr_ifru.ifru_data);
	}
	return -EINVAL;
}

static const struct net_device_ops netdev_ops = {
	.ndo_open		= open,
	.ndo_stop		= stop,
	.ndo_start_xmit		= xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
	.ndo_do_ioctl		= ioctl
};

static void destruct(struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);

	mutex_lock(&wg->device_update_lock);
	peer_remove_all(wg);
	wg->incoming_port = 0;
	destroy_workqueue(wg->handshake_wq);
#ifdef CONFIG_WIREGUARD_PARALLEL
	padata_free(wg->encrypt_pd);
	padata_free(wg->decrypt_pd);
	destroy_workqueue(wg->crypt_wq);
#endif
	routing_table_free(&wg->peer_routing_table);
	memzero_explicit(&wg->static_identity, sizeof(struct noise_static_identity));
	skb_queue_purge(&wg->incoming_handshakes);
	socket_uninit(wg);
	cookie_checker_uninit(&wg->cookie_checker);
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&wg->clear_peers_on_suspend);
#endif
	mutex_unlock(&wg->device_update_lock);
	free_percpu(dev->tstats);

	put_net(wg->creating_net);

	pr_debug("Device %s has been deleted\n", dev->name);
	free_netdev(dev);
}

static void setup(struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	enum { WG_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_SG | NETIF_F_GSO | NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };

	dev->netdev_ops = &netdev_ops;
	dev->destructor = destruct;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->needed_headroom = DATA_PACKET_HEAD_ROOM;
	dev->needed_tailroom = noise_encrypted_len(MESSAGE_PADDING_MULTIPLE);
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	dev->flags |= IFF_NO_QUEUE;
#else
	dev->tx_queue_len = 0;
#endif
	dev->features |= NETIF_F_LLTX;
	dev->features |= WG_NETDEV_FEATURES;
	dev->hw_features |= WG_NETDEV_FEATURES;
	dev->hw_enc_features |= WG_NETDEV_FEATURES;
	dev->mtu = ETH_DATA_LEN - MESSAGE_MINIMUM_LENGTH - sizeof(struct udphdr) - max(sizeof(struct ipv6hdr), sizeof(struct iphdr));

	/* We need to keep the dst around in case of icmp replies. */
	netif_keep_dst(dev);

	memset(wg, 0, sizeof(struct wireguard_device));
}

static int newlink(struct net *src_net, struct net_device *dev, struct nlattr *tb[], struct nlattr *data[])
{
	int ret = -ENOMEM;
	struct wireguard_device *wg = netdev_priv(dev);

	wg->creating_net = get_net(src_net);
	init_rwsem(&wg->static_identity.lock);
	mutex_init(&wg->socket_update_lock);
	mutex_init(&wg->device_update_lock);
	skb_queue_head_init(&wg->incoming_handshakes);
	INIT_WORK(&wg->incoming_handshakes_work, packet_process_queued_handshake_packets);
	pubkey_hashtable_init(&wg->peer_hashtable);
	index_hashtable_init(&wg->index_hashtable);
	routing_table_init(&wg->peer_routing_table);
	INIT_LIST_HEAD(&wg->peer_list);

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		goto error_1;

	wg->handshake_wq = alloc_workqueue("wg-kex-%s", WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_wq)
		goto error_2;

#ifdef CONFIG_WIREGUARD_PARALLEL
	wg->crypt_wq = alloc_workqueue("wg-crypt-%s", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 2, dev->name);
	if (!wg->crypt_wq)
		goto error_3;

	wg->encrypt_pd = padata_alloc_possible(wg->crypt_wq);
	if (!wg->encrypt_pd)
		goto error_4;
	padata_start(wg->encrypt_pd);

	wg->decrypt_pd = padata_alloc_possible(wg->crypt_wq);
	if (!wg->decrypt_pd)
		goto error_5;
	padata_start(wg->decrypt_pd);
#endif

	ret = cookie_checker_init(&wg->cookie_checker, wg);
	if (ret < 0)
		goto error_6;

#ifdef CONFIG_PM_SLEEP
	wg->clear_peers_on_suspend.notifier_call = suspending_clear_noise_peers;
	ret = register_pm_notifier(&wg->clear_peers_on_suspend);
	if (ret < 0)
		goto error_7;
#endif

	ret = register_netdevice(dev);
	if (ret < 0)
		goto error_8;

	pr_debug("Device %s has been created\n", dev->name);

	return 0;

error_8:
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&wg->clear_peers_on_suspend);
error_7:
#endif
	cookie_checker_uninit(&wg->cookie_checker);
error_6:
#ifdef CONFIG_WIREGUARD_PARALLEL
	padata_free(wg->decrypt_pd);
error_5:
	padata_free(wg->encrypt_pd);
error_4:
	destroy_workqueue(wg->crypt_wq);
error_3:
#endif
	destroy_workqueue(wg->handshake_wq);
error_2:
	free_percpu(dev->tstats);
error_1:
	put_net(src_net);
	return ret;
}

static struct rtnl_link_ops link_ops __read_mostly = {
	.kind			= KBUILD_MODNAME,
	.priv_size		= sizeof(struct wireguard_device),
	.setup			= setup,
	.newlink		= newlink,
};

int device_init(void)
{
	return rtnl_link_register(&link_ops);
}

void device_uninit(void)
{
	rtnl_link_unregister(&link_ops);
	rcu_barrier_bh();
}
