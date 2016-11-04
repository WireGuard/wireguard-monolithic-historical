/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "device.h"
#include "peer.h"
#include "socket.h"
#include "packets.h"
#include "messages.h"

#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <net/dst_cache.h>
#include <net/udp_tunnel.h>
#include <net/ipv6.h>


union flowi46 {
	struct flowi4 fl4;
	struct flowi6 fl6;
};

int socket_addr_from_skb(struct sockaddr_storage *sockaddr, struct sk_buff *skb)
{
	struct iphdr *ip4;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;

	addr4 = (struct sockaddr_in *)sockaddr;
	addr6 = (struct sockaddr_in6 *)sockaddr;
	ip4 = ip_hdr(skb);
	ip6 = ipv6_hdr(skb);
	udp = udp_hdr(skb);
	if (ip4->version == 4) {
		addr4->sin_family = AF_INET;
		addr4->sin_port = udp->source;
		addr4->sin_addr.s_addr = ip4->saddr;
	} else if (ip4->version == 6) {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = udp->source;
		addr6->sin6_addr = ip6->saddr;
		addr6->sin6_scope_id = ipv6_iface_scope_id(&ip6->saddr, skb->skb_iif);
		/* TODO: addr6->sin6_flowinfo */
	} else
		return -EINVAL;
	return 0;
}

static inline struct dst_entry *route(struct wireguard_device *wg, union flowi46 *fl, struct sockaddr_storage *addr, struct sock *sock4, struct sock *sock6, struct dst_cache *cache)
{
	if (addr->ss_family == AF_INET) {
		struct rtable *rt;
		struct sockaddr_in *sin4 = (struct sockaddr_in *)addr;

		if (unlikely(!sock4))
			return ERR_PTR(-ENONET);

		memset(&fl->fl4, 0, sizeof(struct flowi4));
		fl->fl4.daddr = sin4->sin_addr.s_addr;
		fl->fl4.fl4_dport = sin4->sin_port;
		fl->fl4.fl4_sport = htons(wg->incoming_port);
		fl->fl4.flowi4_proto = IPPROTO_UDP;

		rt = dst_cache_get_ip4(cache, &fl->fl4.saddr);
		if (rt)
			return &rt->dst;

		security_sk_classify_flow(sock4, flowi4_to_flowi(&fl->fl4));
		rt = ip_route_output_flow(sock_net(sock4), &fl->fl4, sock4);
		if (unlikely(IS_ERR(rt)))
			return ERR_PTR(PTR_ERR(rt));
		dst_cache_set_ip4(cache, &rt->dst, fl->fl4.saddr);
		return &rt->dst;
	} else if (addr->ss_family == AF_INET6) {
#if IS_ENABLED(CONFIG_IPV6)
		int ret;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		struct dst_entry *dst;

		if (unlikely(!sock6))
			return ERR_PTR(-ENONET);

		memset(&fl->fl6, 0, sizeof(struct flowi6));
		fl->fl6.daddr = sin6->sin6_addr;
		fl->fl6.fl6_dport = sin6->sin6_port;
		fl->fl6.fl6_sport = htons(wg->incoming_port);
		fl->fl6.flowi6_oif = sin6->sin6_scope_id;
		fl->fl6.flowi6_proto = IPPROTO_UDP;
		/* TODO: addr6->sin6_flowinfo */

		dst = dst_cache_get_ip6(cache, &fl->fl6.saddr);
		if (dst)
			return dst;

		security_sk_classify_flow(sock6, flowi6_to_flowi(&fl->fl6));
		ret = ipv6_stub->ipv6_dst_lookup(sock_net(sock6), sock6, &dst, &fl->fl6);
		if (unlikely(ret))
			return ERR_PTR(ret);
		dst_cache_set_ip6(cache, dst, &fl->fl6.saddr);
		return dst;
#endif
	}
	return ERR_PTR(-EAFNOSUPPORT);
}

static inline int send(struct net_device *dev, struct sk_buff *skb, struct dst_entry *dst, union flowi46 *fl, struct sockaddr_storage *addr, struct sock *sock4, struct sock *sock6, u8 dscp)
{
	int ret = -EAFNOSUPPORT;

	skb->next = skb->prev = NULL;
	skb->dev = dev;

	if (addr->ss_family == AF_INET) {
		if (unlikely(!sock4)) {
			ret = -ENONET;
			goto err;
		}
		udp_tunnel_xmit_skb((struct rtable *)dst, sock4, skb,
				    fl->fl4.saddr, fl->fl4.daddr,
				    dscp, ip4_dst_hoplimit(dst), 0,
				    fl->fl4.fl4_sport, fl->fl4.fl4_dport,
				    false, false);
		return 0;
	} else if (addr->ss_family == AF_INET6) {
		if (unlikely(!sock6)) {
			ret = -ENONET;
			goto err;
		}
#if IS_ENABLED(CONFIG_IPV6)
		udp_tunnel6_xmit_skb(dst, sock6, skb, dev,
				     &fl->fl6.saddr, &fl->fl6.daddr,
				     dscp, ip6_dst_hoplimit(dst), 0,
				     fl->fl6.fl6_sport, fl->fl6.fl6_dport,
				     false);
		return 0;
#else
		goto err;
#endif
	}

err:
	kfree_skb(skb);
	dst_release(dst);
	return ret;
}

void socket_set_peer_addr(struct wireguard_peer *peer, struct sockaddr_storage *sockaddr)
{
	if (sockaddr->ss_family == AF_INET) {
		read_lock_bh(&peer->endpoint_lock);
		if (!memcmp(sockaddr, &peer->endpoint_addr, sizeof(struct sockaddr_in)))
			goto out;
		read_unlock_bh(&peer->endpoint_lock);
		write_lock_bh(&peer->endpoint_lock);
		memcpy(&peer->endpoint_addr, sockaddr, sizeof(struct sockaddr_in));
	} else if (sockaddr->ss_family == AF_INET6) {
		read_lock_bh(&peer->endpoint_lock);
		if (!memcmp(sockaddr, &peer->endpoint_addr, sizeof(struct sockaddr_in6)))
			goto out;
		read_unlock_bh(&peer->endpoint_lock);
		write_lock_bh(&peer->endpoint_lock);
		memcpy(&peer->endpoint_addr, sockaddr, sizeof(struct sockaddr_in6));
	} else
		return;
	dst_cache_reset(&peer->endpoint_cache);
	write_unlock_bh(&peer->endpoint_lock);
	return;
out:
	read_unlock_bh(&peer->endpoint_lock);
}

int socket_send_skb_to_peer(struct wireguard_peer *peer, struct sk_buff *skb, u8 ds)
{
	struct net_device *dev = netdev_pub(peer->device);
	struct dst_entry *dst;
	union flowi46 fl;
	size_t skb_len = skb->len;
	int ret = 0;

	rcu_read_lock();
	read_lock_bh(&peer->endpoint_lock);

	dst = route(peer->device, &fl, &peer->endpoint_addr, rcu_dereference(peer->device->sock4), rcu_dereference(peer->device->sock6), &peer->endpoint_cache);
	if (unlikely(!dst)) {
		net_dbg_ratelimited("No route to %pISpfsc for peer %Lu\n", &peer->endpoint_addr, peer->internal_id);
		kfree_skb(skb);
		ret = -EHOSTUNREACH;
		goto out;
	} else if (unlikely(dst->dev == dev)) {
		net_dbg_ratelimited("Avoiding routing loop to %pISpfsc for peer %Lu\n", &peer->endpoint_addr, peer->internal_id);
		kfree_skb(skb);
		ret = -ELOOP;
		goto out;
	}

	ret = send(dev, skb, dst, &fl, &peer->endpoint_addr, rcu_dereference(peer->device->sock4), rcu_dereference(peer->device->sock6), ds);
	if (!ret)
		peer->tx_bytes += skb_len;

out:
	read_unlock_bh(&peer->endpoint_lock);
	rcu_read_unlock();

	return ret;
}

int socket_send_buffer_to_peer(struct wireguard_peer *peer, void *buffer, size_t len, u8 ds)
{
	struct sk_buff *skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	memcpy(skb_put(skb, len), buffer, len);
	return socket_send_skb_to_peer(peer, skb, ds);
}

static int send_to_sockaddr(struct sk_buff *skb, struct wireguard_device *wg, struct sockaddr_storage *addr, struct sock *sock4, struct sock *sock6)
{
	struct dst_entry *dst;
	struct net_device *dev = netdev_pub(wg);
	union flowi46 fl;

	dst = route(wg, &fl, addr, sock4, sock6, NULL);
	if (IS_ERR(dst)) {
		net_dbg_ratelimited("No route to %pISpfsc\n", addr);
		kfree_skb(skb);
		return PTR_ERR(dst);
	} else if (unlikely(dst->dev == netdev_pub(wg))) {
		net_dbg_ratelimited("Avoiding routing loop to %pISpfsc\n", addr);
		dst_release(dst);
		kfree_skb(skb);
		return -ELOOP;
	}

	return send(dev, skb, dst, &fl, addr, sock4, sock6, 0);
}

int socket_send_buffer_as_reply_to_skb(struct sk_buff *in_skb, void *out_buffer, size_t len, struct wireguard_device *wg)
{
	int ret = 0;
	struct sk_buff *skb;
	struct sockaddr_storage addr = { 0 };

	if (unlikely(!in_skb))
		return -EINVAL;
	ret = socket_addr_from_skb(&addr, in_skb);
	if (ret < 0)
		return ret;

	skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	memcpy(skb_put(skb, len), out_buffer, len);

	rcu_read_lock();
	ret = send_to_sockaddr(skb, wg, &addr, rcu_dereference(wg->sock4), rcu_dereference(wg->sock6));
	rcu_read_unlock();

	return ret;
}

static int receive(struct sock *sk, struct sk_buff *skb)
{
	struct wireguard_device *wg;

	if (unlikely(!sk))
		goto err;
	wg = sk->sk_user_data;
	if (unlikely(!wg))
		goto err;
	packet_receive(wg, skb);
	return 0;

err:
	kfree_skb(skb);
	return 0;
}

/* Generates a default port from the interface name.
 * wg0 --> 51820
 * wg1 --> 51821
 * wg2 --> 51822
 * wg100 --> 51920
 * wg60000 --> 46285
 * blahbla --> 51820
 * 50 --> 51870
 */
static uint16_t generate_default_incoming_port(struct wireguard_device *wg)
{
	uint16_t port = 51820;
	unsigned long parsed;
	char *name, *digit_begin;
	size_t len;

	ASSERT_RTNL();

	name = netdev_pub(wg)->name;
	len = strlen(name);
	if (!len)
		return port;
	digit_begin = name + len - 1;
	while (digit_begin >= name) {
		if (isdigit(*digit_begin))
			--digit_begin;
		else
			break;
	}
	++digit_begin;
	if (!*digit_begin)
		return port;
	if (!kstrtoul(digit_begin, 10, &parsed))
		port += parsed;
	if (!port)
		++port;
	return port;
}

static inline void sock_free(struct sock *sock)
{
	if (unlikely(!sock))
		return;
	sk_clear_memalloc(sock);
	udp_tunnel_sock_release(sock->sk_socket);
}

static inline void set_sock_opts(struct socket *sock)
{
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_sndbuf = INT_MAX;
	sk_set_memalloc(sock->sk);
}

int socket_init(struct wireguard_device *wg)
{
	int ret = 0;
	struct socket *new4 = NULL;
	struct udp_port_cfg port4 = {
		.family = AF_INET,
		.local_ip.s_addr = htonl(INADDR_ANY),
		.use_udp_checksums = true
	};
#if IS_ENABLED(CONFIG_IPV6)
	struct socket *new6 = NULL;
	struct udp_port_cfg port6 = {
		.family = AF_INET6,
		.local_ip6 = IN6ADDR_ANY_INIT,
		.use_udp6_tx_checksums = true,
		.use_udp6_rx_checksums = true,
		.ipv6_v6only = true
	};
#endif
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = wg,
		.encap_type = 1,
		.encap_rcv = receive
	};

	mutex_lock(&wg->socket_update_lock);

	if (rcu_dereference_protected(wg->sock4, lockdep_is_held(&wg->socket_update_lock)) ||
	    rcu_dereference_protected(wg->sock6, lockdep_is_held(&wg->socket_update_lock))) {
		ret = -EADDRINUSE;
		goto out;
	}

	if (!wg->incoming_port)
		wg->incoming_port = generate_default_incoming_port(wg);
	port4.local_udp_port =
#if IS_ENABLED(CONFIG_IPV6)
		port6.local_udp_port =
#endif
		htons(wg->incoming_port);

	ret = udp_sock_create(wg->creating_net, &port4, &new4);
	if (ret < 0) {
		pr_err("Could not create IPv4 socket\n");
		goto out;
	}

	set_sock_opts(new4);
	setup_udp_tunnel_sock(wg->creating_net, new4, &cfg);
	rcu_assign_pointer(wg->sock4, new4->sk);

#if IS_ENABLED(CONFIG_IPV6)
	ret = udp_sock_create(wg->creating_net, &port6, &new6);
	if (ret < 0) {
		pr_err("Could not create IPv6 socket\n");
		udp_tunnel_sock_release(new4);
		rcu_assign_pointer(wg->sock4, NULL);
		goto out;
	}
	set_sock_opts(new6);
	setup_udp_tunnel_sock(wg->creating_net, new6, &cfg);
	rcu_assign_pointer(wg->sock6, new6->sk);
#endif

out:
	mutex_unlock(&wg->socket_update_lock);
	return ret;
}

void socket_uninit(struct wireguard_device *wg)
{
	struct sock *old4, *old6;
	mutex_lock(&wg->socket_update_lock);
	old4 = rcu_dereference_protected(wg->sock4, lockdep_is_held(&wg->socket_update_lock));
	old6 = rcu_dereference_protected(wg->sock6, lockdep_is_held(&wg->socket_update_lock));
	rcu_assign_pointer(wg->sock4, NULL);
	rcu_assign_pointer(wg->sock6, NULL);
	mutex_unlock(&wg->socket_update_lock);
	synchronize_rcu();
	sock_free(old4);
	sock_free(old6);
}
