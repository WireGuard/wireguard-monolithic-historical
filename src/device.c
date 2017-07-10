/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "packets.h"
#include "socket.h"
#include "timers.h"
#include "device.h"
#include "config.h"
#include "ratelimiter.h"
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

static LIST_HEAD(device_list);

static int open(struct net_device *dev)
{
	int ret;
	struct wireguard_peer *peer, *temp;
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
	peer_for_each (wg, peer, temp, true) {
		timers_init_peer(peer);
		packet_send_queue(peer);
		if (peer->persistent_keepalive_interval)
			packet_send_keepalive(peer);
	}
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int suspending_clear_noise_peers(struct notifier_block *nb, unsigned long action, void *data)
{
	struct wireguard_device *wg;
	struct wireguard_peer *peer, *temp;

	if (action != PM_HIBERNATION_PREPARE && action != PM_SUSPEND_PREPARE)
		return 0;

	rtnl_lock();
	list_for_each_entry (wg, &device_list, device_list) {
		peer_for_each (wg, peer, temp, true) {
			noise_handshake_clear(&peer->handshake);
			noise_keypairs_clear(&peer->keypairs);
			if (peer->timers_enabled)
				del_timer(&peer->timer_kill_ephemerals);
		}
	}
	rtnl_unlock();
	rcu_barrier_bh();

	return 0;
}
static struct notifier_block clear_peers_on_suspend = { .notifier_call = suspending_clear_noise_peers };
#endif

static int stop(struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	struct wireguard_peer *peer, *temp;
	peer_for_each (wg, peer, temp, true) {
		timers_uninit_peer(peer);
		noise_handshake_clear(&peer->handshake);
		noise_keypairs_clear(&peer->keypairs);
		if (peer->timers_enabled)
			del_timer(&peer->timer_kill_ephemerals);
	}
	skb_queue_purge(&wg->incoming_handshakes);
	socket_uninit(wg);
	return 0;
}

static netdev_tx_t xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	struct wireguard_peer *peer;
	struct sk_buff *next;
	int ret;

	if (unlikely(dev_recursion_level() > 4)) {
		ret = -ELOOP;
		net_dbg_ratelimited("%s: Routing loop detected\n", dev->name);
		goto err;
	}

	if (unlikely(skb_examine_untrusted_ip_hdr(skb) != skb->protocol)) {
		ret = -EPROTONOSUPPORT;
		net_dbg_ratelimited("%s: Invalid IP packet\n", dev->name);
		goto err;
	}

	peer = routing_table_lookup_dst(&wg->peer_routing_table, skb);
	if (unlikely(!peer)) {
		ret = -ENOKEY;
		net_dbg_skb_ratelimited("%s: No peer is configured for %pISc\n", dev->name, skb);
		goto err;
	}

	read_lock_bh(&peer->endpoint_lock);
	ret = peer->endpoint.addr.sa_family != AF_INET && peer->endpoint.addr.sa_family != AF_INET6;
	read_unlock_bh(&peer->endpoint_lock);
	if (unlikely(ret)) {
		ret = -EDESTADDRREQ;
		net_dbg_ratelimited("%s: No valid endpoint has been configured or discovered for peer %Lu\n", dev->name, peer->internal_id);
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
	do {
		next = skb->next;
		skb->next = skb->prev = NULL;

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb))
			continue;

		/* We only need to keep the original dst around for icmp,
		 * so at this point we're in a position to drop it. */
		skb_dst_drop(skb);

		skb_queue_tail(&peer->tx_packet_queue, skb);
	} while ((skb = next) != NULL);

	packet_send_queue(peer);
	peer_put(peer);
	return NETDEV_TX_OK;

err_peer:
	peer_put(peer);
err:
	++dev->stats.tx_errors;
	if (skb->protocol == htons(ETH_P_IP))
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	else if (skb->protocol == htons(ETH_P_IPV6))
		icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
	kfree_skb(skb);
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

	rtnl_lock();
	list_del(&wg->device_list);
	rtnl_unlock();
	mutex_lock(&wg->device_update_lock);
	peer_remove_all(wg);
	wg->incoming_port = 0;
	destroy_workqueue(wg->incoming_handshake_wq);
	destroy_workqueue(wg->peer_wq);
#ifdef CONFIG_WIREGUARD_PARALLEL
	padata_free(wg->encrypt_pd);
	padata_free(wg->decrypt_pd);
	destroy_workqueue(wg->crypt_wq);
#endif
	routing_table_free(&wg->peer_routing_table);
	ratelimiter_uninit();
	memzero_explicit(&wg->static_identity, sizeof(struct noise_static_identity));
	skb_queue_purge(&wg->incoming_handshakes);
	socket_uninit(wg);
	mutex_unlock(&wg->device_update_lock);
	free_percpu(dev->tstats);
	free_percpu(wg->incoming_handshakes_worker);
	put_net(wg->creating_net);

	pr_debug("%s: Interface deleted\n", dev->name);
	free_netdev(dev);
}

static void setup(struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	enum { WG_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_SG | NETIF_F_GSO | NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };

	dev->netdev_ops = &netdev_ops;
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

static int newlink(struct net *src_net, struct net_device *dev, struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack)
{
	int ret = -ENOMEM, cpu;
	struct wireguard_device *wg = netdev_priv(dev);

	wg->creating_net = get_net(src_net);
	init_rwsem(&wg->static_identity.lock);
	mutex_init(&wg->socket_update_lock);
	mutex_init(&wg->device_update_lock);
	skb_queue_head_init(&wg->incoming_handshakes);
	pubkey_hashtable_init(&wg->peer_hashtable);
	index_hashtable_init(&wg->index_hashtable);
	routing_table_init(&wg->peer_routing_table);
	cookie_checker_init(&wg->cookie_checker, wg);
	INIT_LIST_HEAD(&wg->peer_list);

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		goto error_1;

	wg->incoming_handshakes_worker = alloc_percpu(struct handshake_worker);
	if (!wg->incoming_handshakes_worker)
		goto error_2;
	for_each_possible_cpu (cpu) {
		per_cpu_ptr(wg->incoming_handshakes_worker, cpu)->wg = wg;
		INIT_WORK(&per_cpu_ptr(wg->incoming_handshakes_worker, cpu)->work, packet_process_queued_handshake_packets);
	}
	atomic_set(&wg->incoming_handshake_seqnr, 0);

	wg->incoming_handshake_wq = alloc_workqueue("wg-kex-%s", WQ_CPU_INTENSIVE | WQ_FREEZABLE, 0, dev->name);
	if (!wg->incoming_handshake_wq)
		goto error_3;

	wg->peer_wq = alloc_workqueue("wg-kex-%s", WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!wg->peer_wq)
		goto error_4;

#ifdef CONFIG_WIREGUARD_PARALLEL
	wg->crypt_wq = alloc_workqueue("wg-crypt-%s", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 2, dev->name);
	if (!wg->crypt_wq)
		goto error_5;

	wg->encrypt_pd = padata_alloc_possible(wg->crypt_wq);
	if (!wg->encrypt_pd)
		goto error_6;
	padata_start(wg->encrypt_pd);

	wg->decrypt_pd = padata_alloc_possible(wg->crypt_wq);
	if (!wg->decrypt_pd)
		goto error_7;
	padata_start(wg->decrypt_pd);
#endif

	ret = ratelimiter_init();
	if (ret < 0)
		goto error_8;

	ret = register_netdevice(dev);
	if (ret < 0)
		goto error_9;

	list_add(&wg->device_list, &device_list);

	/* We wait until the end to assign priv_destructor, so that register_netdevice doesn't
	 * call it for us if it fails. */
	dev->priv_destructor = destruct;

	pr_debug("%s: Interface created\n", dev->name);
	return ret;

error_9:
	ratelimiter_uninit();
error_8:
#ifdef CONFIG_WIREGUARD_PARALLEL
	padata_free(wg->decrypt_pd);
error_7:
	padata_free(wg->encrypt_pd);
error_6:
	destroy_workqueue(wg->crypt_wq);
error_5:
#endif
	destroy_workqueue(wg->peer_wq);
error_4:
	destroy_workqueue(wg->incoming_handshake_wq);
error_3:
	free_percpu(wg->incoming_handshakes_worker);
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

int __init device_init(void)
{
#ifdef CONFIG_PM_SLEEP
	int ret = register_pm_notifier(&clear_peers_on_suspend);
	if (ret)
		return ret;
#endif
	return rtnl_link_register(&link_ops);
}

void __exit device_uninit(void)
{
	rtnl_link_unregister(&link_ops);
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&clear_peers_on_suspend);
#endif
	rcu_barrier_bh();
}
