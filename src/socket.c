/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "device.h"
#include "peer.h"
#include "socket.h"
#include "packets.h"
#include "messages.h"

#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <net/udp_tunnel.h>
#include <net/ipv6.h>

static inline int send4(struct wireguard_device *wg, struct sk_buff *skb, struct endpoint *endpoint, uint8_t ds, struct dst_cache *cache)
{
	struct flowi4 fl = {
		.saddr = endpoint->src4.s_addr,
		.daddr = endpoint->addr4.sin_addr.s_addr,
		.fl4_dport = endpoint->addr4.sin_port,
		.fl4_sport = htons(wg->incoming_port),
		.flowi4_proto = IPPROTO_UDP
	};
	struct rtable *rt = NULL;
	struct sock *sock;
	int ret = 0;

	skb->next = skb->prev = NULL;
	skb->dev = netdev_pub(wg);

	rcu_read_lock();
	sock = rcu_dereference(wg->sock4);

	if (unlikely(!sock)) {
		ret = -ENONET;
		goto err;
	}

	if (cache)
		rt = dst_cache_get_ip4(cache, &fl.saddr);

	if (!rt) {
		security_sk_classify_flow(sock, flowi4_to_flowi(&fl));
		rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		if (unlikely(IS_ERR(rt) && PTR_ERR(rt) == -EINVAL && fl.saddr)) {
			endpoint->src4.s_addr = fl.saddr = 0;
			if (cache)
				dst_cache_reset(cache);
			rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		}
		if (unlikely(IS_ERR(rt))) {
			ret = PTR_ERR(rt);
			net_dbg_ratelimited("No route to %pISpfsc, error %d\n", &endpoint->addr_storage, ret);
			goto err;
		} else if (unlikely(rt->dst.dev == skb->dev)) {
			dst_release(&rt->dst);
			ret = -ELOOP;
			net_dbg_ratelimited("Avoiding routing loop to %pISpfsc\n", &endpoint->addr_storage);
			goto err;
		}
		if (cache)
			dst_cache_set_ip4(cache, &rt->dst, fl.saddr);
	}

	udp_tunnel_xmit_skb(rt, sock, skb,
			    fl.saddr, fl.daddr,
			    ds, ip4_dst_hoplimit(&rt->dst), 0,
			    fl.fl4_sport, fl.fl4_dport,
			    false, false);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock();
	return ret;
}

static inline int send6(struct wireguard_device *wg, struct sk_buff *skb, struct endpoint *endpoint, uint8_t ds, struct dst_cache *cache)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct flowi6 fl = {
		.saddr = endpoint->src6,
		.daddr = endpoint->addr6.sin6_addr,
		.fl6_dport = endpoint->addr6.sin6_port,
		.fl6_sport = htons(wg->incoming_port),
		.flowi6_oif = endpoint->addr6.sin6_scope_id,
		.flowi6_proto = IPPROTO_UDP
		/* TODO: addr->sin6_flowinfo */
	};
	struct dst_entry *dst = NULL;
	struct sock *sock;
	int ret = 0;

	skb->next = skb->prev = NULL;
	skb->dev = netdev_pub(wg);

	rcu_read_lock();
	sock = rcu_dereference(wg->sock6);

	if (unlikely(!sock)) {
		ret = -ENONET;
		goto err;
	}

	if (cache)
		dst = dst_cache_get_ip6(cache, &fl.saddr);

	if (!dst) {
		security_sk_classify_flow(sock, flowi6_to_flowi(&fl));
		if (unlikely(!ipv6_addr_any(&fl.saddr) && !ipv6_chk_addr(sock_net(sock), &fl.saddr, NULL, 0))) {
			endpoint->src6 = fl.saddr = in6addr_any;
			if (cache)
				dst_cache_reset(cache);
		}
		ret = ipv6_stub->ipv6_dst_lookup(sock_net(sock), sock, &dst, &fl);
		if (unlikely(ret)) {
			net_dbg_ratelimited("No route to %pISpfsc, error %d\n", &endpoint->addr_storage, ret);
			goto err;
		} else if (unlikely(dst->dev == skb->dev)) {
			dst_release(dst);
			ret = -ELOOP;
			net_dbg_ratelimited("Avoiding routing loop to %pISpfsc\n", &endpoint->addr_storage);
			goto err;
		}
		if (cache)
			dst_cache_set_ip6(cache, dst, &fl.saddr);
	}

	udp_tunnel6_xmit_skb(dst, sock, skb, skb->dev,
			     &fl.saddr, &fl.daddr,
			     ds, ip6_dst_hoplimit(dst), 0,
			     fl.fl6_sport, fl.fl6_dport,
			     false);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock();
	return ret;
#else
	return -EAFNOSUPPORT;
#endif
}

int socket_send_skb_to_peer(struct wireguard_peer *peer, struct sk_buff *skb, uint8_t ds)
{
	size_t skb_len = skb->len;
	int ret = -EAFNOSUPPORT;

	read_lock_bh(&peer->endpoint_lock);
	if (peer->endpoint.addr_storage.ss_family == AF_INET)
		ret = send4(peer->device, skb, &peer->endpoint, ds, &peer->endpoint_cache);
	else if (peer->endpoint.addr_storage.ss_family == AF_INET6)
		ret = send6(peer->device, skb, &peer->endpoint, ds, &peer->endpoint_cache);
	if (likely(!ret))
		peer->tx_bytes += skb_len;
	read_unlock_bh(&peer->endpoint_lock);

	return ret;
}

int socket_send_buffer_to_peer(struct wireguard_peer *peer, void *buffer, size_t len, uint8_t ds)
{
	struct sk_buff *skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	memcpy(skb_put(skb, len), buffer, len);
	return socket_send_skb_to_peer(peer, skb, ds);
}

int socket_send_buffer_as_reply_to_skb(struct wireguard_device *wg, struct sk_buff *in_skb, void *out_buffer, size_t len)
{
	int ret = 0;
	struct sk_buff *skb;
	struct endpoint endpoint;

	if (unlikely(!in_skb))
		return -EINVAL;
	ret = socket_endpoint_from_skb(&endpoint, in_skb);
	if (unlikely(ret < 0))
		return ret;

	skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	memcpy(skb_put(skb, len), out_buffer, len);

	if (endpoint.addr_storage.ss_family == AF_INET)
		ret = send4(wg, skb, &endpoint, 0, NULL);
	else if (endpoint.addr_storage.ss_family == AF_INET6)
		ret = send6(wg, skb, &endpoint, 0, NULL);
	else
		ret = -EAFNOSUPPORT;

	return ret;
}

int socket_endpoint_from_skb(struct endpoint *endpoint, struct sk_buff *skb)
{
	memset(endpoint, 0, sizeof(struct endpoint));
	if (ip_hdr(skb)->version == 4) {
		endpoint->addr4.sin_family = AF_INET;
		endpoint->addr4.sin_port = udp_hdr(skb)->source;
		endpoint->addr4.sin_addr.s_addr = ip_hdr(skb)->saddr;
		endpoint->src4.s_addr = ip_hdr(skb)->daddr;
	} else if (ip_hdr(skb)->version == 6) {
		endpoint->addr6.sin6_family = AF_INET6;
		endpoint->addr6.sin6_port = udp_hdr(skb)->source;
		endpoint->addr6.sin6_addr = ipv6_hdr(skb)->saddr;
		endpoint->addr6.sin6_scope_id = ipv6_iface_scope_id(&ipv6_hdr(skb)->saddr, skb->skb_iif);
		/* TODO: endpoint->addr6.sin6_flowinfo */
		endpoint->src6 = ipv6_hdr(skb)->daddr;
	} else
		return -EINVAL;
	return 0;
}

void socket_set_peer_endpoint(struct wireguard_peer *peer, struct endpoint *endpoint)
{
	if (endpoint->addr_storage.ss_family == AF_INET) {
		read_lock_bh(&peer->endpoint_lock);
		if (likely(peer->endpoint.addr4.sin_family == AF_INET &&
			   peer->endpoint.addr4.sin_port == endpoint->addr4.sin_port &&
			   peer->endpoint.addr4.sin_addr.s_addr == endpoint->addr4.sin_addr.s_addr &&
			   peer->endpoint.src4.s_addr == endpoint->src4.s_addr))
			goto out;
		read_unlock_bh(&peer->endpoint_lock);
		write_lock_bh(&peer->endpoint_lock);
		peer->endpoint.addr4 = endpoint->addr4;
		peer->endpoint.src4 = endpoint->src4;
	} else if (endpoint->addr_storage.ss_family == AF_INET6) {
		read_lock_bh(&peer->endpoint_lock);
		if (likely(peer->endpoint.addr6.sin6_family == AF_INET6 &&
			   peer->endpoint.addr6.sin6_port == endpoint->addr6.sin6_port &&
			   /* TODO: peer->endpoint.addr6.sin6_flowinfo == endpoint->addr6.sin6_flowinfo && */
			   ipv6_addr_equal(&peer->endpoint.addr6.sin6_addr, &endpoint->addr6.sin6_addr) &&
			   peer->endpoint.addr6.sin6_scope_id == endpoint->addr6.sin6_scope_id &&
			   ipv6_addr_equal(&peer->endpoint.src6, &endpoint->src6)))
			goto out;
		read_unlock_bh(&peer->endpoint_lock);
		write_lock_bh(&peer->endpoint_lock);
		peer->endpoint.addr6 = endpoint->addr6;
		peer->endpoint.src6 = endpoint->src6;
	} else
		return;
	dst_cache_reset(&peer->endpoint_cache);
	write_unlock_bh(&peer->endpoint_lock);
	return;
out:
	read_unlock_bh(&peer->endpoint_lock);
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
