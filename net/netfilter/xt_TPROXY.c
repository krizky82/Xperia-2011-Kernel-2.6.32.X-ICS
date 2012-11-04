/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (c) 2006-2007 BalaBit IT Ltd.
 * Author: Balazs Scheidler, Krisztian Kovacs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/inet_sock.h>
#include <linux/inetdevice.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#endif

#include <net/netfilter/nf_tproxy_core.h>
#include <linux/netfilter/xt_TPROXY.h>

static bool tproxy_sk_is_transparent(struct sock *sk)
{
	if (sk->sk_state != TCP_TIME_WAIT) {
		if (inet_sk(sk)->transparent)
			return true;
		sock_put(sk);
	} else {
		if (inet_twsk(sk)->tw_transparent)
			return true;
		inet_twsk_put(inet_twsk(sk));
	}
	return false;
}

static inline __be32
tproxy_laddr4(struct sk_buff *skb, __be32 user_laddr, __be32 daddr)
{
	struct in_device *indev;
	__be32 laddr;

	if (user_laddr)
		return user_laddr;

	laddr = 0;
	rcu_read_lock();
	indev = __in_dev_get_rcu(skb->dev);
	for_primary_ifa(indev) {
		laddr = ifa->ifa_local;
		break;
	} endfor_ifa(indev);
	rcu_read_unlock();

	return laddr ? laddr : daddr;
}

static unsigned int
tproxy_tg4(struct sk_buff *skb, __be32 laddr, __be16 lport,
	   u_int32_t mark_mask, u_int32_t mark_value)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct udphdr _hdr, *hp;
	struct sock *sk;

	hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
	if (hp == NULL) {
		pr_debug("TPROXY: packet is too short to contain a transport header, dropping\n");
		return NF_DROP;
	}

	/* check if there's an ongoing connection on the packet
	 * addresses, this happens if the redirect already happened
	 * and the current packet belongs to an already established
	 * connection */
	sk = nf_tproxy_get_sock_v4(dev_net(skb->dev), iph->protocol,
				   iph->saddr, iph->daddr,
				   hp->source, hp->dest,
				   skb->dev, NFT_LOOKUP_ESTABLISHED);

	/* udp has no TCP_TIME_WAIT state, so we never enter here */
	if (sk && sk->sk_state == TCP_TIME_WAIT) {
		struct tcphdr _hdr, *hp;

		hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return NF_DROP;
		
		if (hp->syn && !hp->rst && !hp->ack && !hp->fin) {
			struct sock *sk2;
			
			/* Hm.. we got a SYN to a TIME_WAIT socket, let's see if
			 * there's a listener on the redirected port
			 */
			sk2 = nf_tproxy_get_sock_v4(dev_net(skb->dev), iph->protocol,
						    iph->saddr, tproxy_laddr4(skb, laddr, iph->daddr),
						    hp->source, lport ? lport : hp->dest,
						    skb->dev, NFT_LOOKUP_LISTENER);
			if (sk2) {
				
				/* yeah, there's one, let's kill the TIME_WAIT
				 * socket and redirect to the listener
				 */
				inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
				inet_twsk_put(inet_twsk(sk));
				sk = sk2;
			}
		}
	} else if (!sk) {
		/* no there's no established connection, check if
		 * there's a listener on the redirected addr/port */
		sk = nf_tproxy_get_sock_v4(dev_net(skb->dev), iph->protocol,
					   iph->saddr, tproxy_laddr4(skb, laddr, iph->daddr),
					   hp->source, lport ? lport : hp->dest,
					   skb->dev, NFT_LOOKUP_LISTENER);
	}
	/* NOTE: assign_sock consumes our sk reference */
	if (sk && tproxy_sk_is_transparent(sk)) {
		/* This should be in a separate target, but we don't do multiple
		   targets on the same rule yet */
		skb->mark = (skb->mark & ~mark_mask) ^ mark_value;

		pr_debug("TPROXY: redirecting: proto %u %08x:%u -> %08x:%u, mark: %x\n",
			 iph->protocol, ntohl(iph->daddr), ntohs(hp->dest),
			 ntohl(laddr), ntohs(lport), skb->mark);

		nf_tproxy_assign_sock(skb, sk);
		return NF_ACCEPT;
	}

	pr_debug("TPROXY: no socket, dropping: proto %u %08x:%u -> %08x:%u, mark: %x\n",
		 iph->protocol, ntohl(iph->daddr), ntohs(hp->dest),
		 ntohl(laddr), ntohs(lport), skb->mark);
	return NF_DROP;
}

static unsigned int
tproxy_tg4_v0(struct sk_buff *skb, const struct xt_target_param *par)
{
	const struct xt_tproxy_target_info *tgi = par->targinfo;

	return tproxy_tg4(skb, tgi->laddr, tgi->lport, tgi->mark_mask, tgi->mark_value);
}

static unsigned int
tproxy_tg4_v1(struct sk_buff *skb, const struct xt_target_param *par)
{
	const struct xt_tproxy_target_info_v1 *tgi = par->targinfo;

	return tproxy_tg4(skb, tgi->laddr.ip, tgi->lport, tgi->mark_mask, tgi->mark_value);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)

static inline const struct in6_addr *
tproxy_laddr6(struct sk_buff *skb, const struct in6_addr *user_laddr,
	      const struct in6_addr *daddr)
{
	struct inet6_dev *indev;
	struct inet6_ifaddr *ifa;
	struct in6_addr *laddr;

	if (!ipv6_addr_any(user_laddr))
		return user_laddr;
	laddr = NULL;

	rcu_read_lock();
	indev = __in6_dev_get(skb->dev);
	if (indev && (ifa = indev->addr_list)) {
		laddr = &ifa->addr;
	}
	rcu_read_unlock();

	return laddr ? laddr : daddr;
}


static unsigned int
tproxy_tg6_v1(struct sk_buff *skb, const struct xt_target_param *par)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	const struct xt_tproxy_target_info_v1 *tgi = par->targinfo;
	struct udphdr _hdr, *hp;
	struct sock *sk;
	int thoff;
	int tproto;

	tproto = ipv6_find_hdr(skb, &thoff, -1, NULL);
	if (tproto < 0) {
		pr_debug("TPROXY: Unable to find transport header in IPv6 packet, dropping\n");
		return NF_DROP;
	}

	hp = skb_header_pointer(skb, thoff, sizeof(_hdr), &_hdr);
	if (hp == NULL) {
		pr_debug("TPROXY: Unable to grab transport header contents in IPv6 packet, dropping\n");
		return NF_DROP;
	}

	/* check if there's an ongoing connection on the packet
	 * addresses, this happens if the redirect already happened
	 * and the current packet belongs to an already established
	 * connection */
	sk = nf_tproxy_get_sock_v6(dev_net(skb->dev), tproto,
				   &iph->saddr, &iph->daddr,
				   hp->source, hp->dest,
				   par->in, NFT_LOOKUP_ESTABLISHED);

	/* udp has no TCP_TIME_WAIT state, so we never enter here */
	if (sk && sk->sk_state == TCP_TIME_WAIT) {
		struct tcphdr _hdr, *hp;

		hp = skb_header_pointer(skb, thoff, sizeof(_hdr), &_hdr);
		if (hp == NULL) {
			pr_debug("TPROXY: Unable to grab TCP transport header contents in IPv6 packet, dropping\n");
			return NF_DROP;
		}

		if (hp->syn && !hp->rst && !hp->ack && !hp->fin) {
			struct sock *sk2;
			

			/* Hm.. we got a SYN to a TIME_WAIT socket, let's see if
			 * there's a listener on the redirected port
			 */
			sk2 = nf_tproxy_get_sock_v6(dev_net(skb->dev), tproto,
						    &iph->saddr, tproxy_laddr6(skb, &tgi->laddr.in6, &iph->daddr),
						    hp->source, tgi->lport ? tgi->lport : hp->dest,
						    par->in, NFT_LOOKUP_LISTENER);
			if (sk2) {
				
				/* yeah, there's one, let's kill the TIME_WAIT
				 * socket and redirect to the listener
				 */
				inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
				inet_twsk_put(inet_twsk(sk));
				sk = sk2;
			}
		}
	} else if (!sk) {
		/* no there's no established connection, check if
		 * there's a listener on the redirected addr/port */
		sk = nf_tproxy_get_sock_v6(dev_net(skb->dev), tproto,
					   &iph->saddr, tproxy_laddr6(skb, &tgi->laddr.in6, &iph->daddr),
					   hp->source, tgi->lport ? tgi->lport : hp->dest,
					   par->in, NFT_LOOKUP_LISTENER);
	}
	/* NOTE: assign_sock consumes our sk reference */
	if (sk && tproxy_sk_is_transparent(sk)) {
		/* This should be in a separate target, but we don't do multiple
		   targets on the same rule yet */
		skb->mark = (skb->mark & ~tgi->mark_mask) ^ tgi->mark_value;

		pr_debug("TPROXY: redirecting: proto %u %pI6:%u -> %pI6:%u, mark: %x\n",
			 tproto, &iph->saddr, ntohs(hp->dest),
			 &tgi->laddr.in6, ntohs(tgi->lport), skb->mark);

		nf_tproxy_assign_sock(skb, sk);
		return NF_ACCEPT;
	}

	pr_debug("TPROXY: no socket, dropping: proto %u %pI6:%u -> %pI6:%u, mark: %x\n",
		 tproto, &iph->saddr, ntohs(hp->dest),
		 &tgi->laddr.in6, ntohs(tgi->lport), skb->mark);
	return NF_DROP;
}

static bool tproxy_tg6_check(const struct xt_tgchk_param *par)
{
	const struct ip6t_ip6 *i = par->entryinfo;

	if ((i->proto == IPPROTO_TCP || i->proto == IPPROTO_UDP)
	    && !(i->flags & IP6T_INV_PROTO))
		return true;

	pr_info("xt_TPROXY: Can be used only in combination with "
		"either -p tcp or -p udp\n");
	return false;
}
#endif


static bool tproxy_tg4_check(const struct xt_tgchk_param *par)
{
	const struct ipt_ip *i = par->entryinfo;

	if ((i->proto == IPPROTO_TCP || i->proto == IPPROTO_UDP)
	    && !(i->invflags & IPT_INV_PROTO))
		return true;

	pr_info("xt_TPROXY: Can be used only in combination with "
		"either -p tcp or -p udp\n");
	return false;
}

static struct xt_target tproxy_tg_reg[] __read_mostly = {
	{
		.name		= "TPROXY",
		.family		= NFPROTO_IPV4,
		.table		= "mangle",
		.target		= tproxy_tg4_v0,
		.revision	= 0,
		.targetsize	= sizeof(struct xt_tproxy_target_info),
		.checkentry	= tproxy_tg4_check,
		.hooks		= 1 << NF_INET_PRE_ROUTING,
		.me		= THIS_MODULE,
	},
	{
		.name		= "TPROXY",
		.family		= NFPROTO_IPV4,
		.table		= "mangle",
		.target		= tproxy_tg4_v1,
		.revision	= 1,
		.targetsize	= sizeof(struct xt_tproxy_target_info_v1),
		.checkentry	= tproxy_tg4_check,
		.hooks		= 1 << NF_INET_PRE_ROUTING,
		.me		= THIS_MODULE,
	},
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	{
		.name		= "TPROXY",
		.family		= NFPROTO_IPV6,
		.table		= "mangle",
		.target		= tproxy_tg6_v1,
		.revision	= 1,
		.targetsize	= sizeof(struct xt_tproxy_target_info_v1),
		.checkentry	= tproxy_tg6_check,
		.hooks		= 1 << NF_INET_PRE_ROUTING,
		.me		= THIS_MODULE,
	},
#endif

};

static int __init tproxy_tg_init(void)
{
	nf_defrag_ipv4_enable();
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	nf_defrag_ipv6_enable();
#endif

	return xt_register_targets(tproxy_tg_reg, ARRAY_SIZE(tproxy_tg_reg));
}

static void __exit tproxy_tg_exit(void)
{
	xt_unregister_targets(tproxy_tg_reg, ARRAY_SIZE(tproxy_tg_reg));
}

module_init(tproxy_tg_init);
module_exit(tproxy_tg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krisztian Kovacs");
MODULE_DESCRIPTION("Netfilter transparent proxy (TPROXY) target module.");
MODULE_ALIAS("ipt_TPROXY");
MODULE_ALIAS("ip6t_TPROXY");
