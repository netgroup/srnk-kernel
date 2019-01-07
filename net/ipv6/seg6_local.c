/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *
 *  Andrea Mayer: extended David's framework and implemented End.AD behaviour
 *  (also known as dynamic proxy).
 *
 *
 *  This program is free software; you can redistribute it and/or
 *        modify it under the terms of the GNU General Public License
 *        as published by the Free Software Foundation; either version
 *        2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/lwtunnel.h>
#include <net/netevent.h>
#include <net/netns/generic.h>
#include <net/ip6_fib.h>
#include <net/route.h>
#include <net/seg6.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/dst_cache.h>
#ifdef CONFIG_IPV6_SEG6_HMAC
#include <net/seg6_hmac.h>
#endif
#include <linux/etherdevice.h>

enum {
	NH_PROTO_UNSPEC = 0,
	NH_PROTO_ETH,
	NH_PROTO_IPV4,
	NH_PROTO_IPV6,
	__NH_PROTO_MAX,
};

#define NH_PROTO_MAX		(__NH_PROTO_MAX - 1)
#define NH_PROTO_INVALID	((int) -1)

/* $Andrea */
static int nh_protos[NH_PROTO_MAX + 1] = {
	[NH_PROTO_ETH]  =  (SEG6_LOCAL_NHETH),
	[NH_PROTO_IPV4] =  (SEG6_LOCAL_NH4),
	[NH_PROTO_IPV6] =  (SEG6_LOCAL_NH6),
};

/* $Andrea */
inline struct seg6_local_pernet_data *seg6_local_pernet(struct net *net)
{
	struct seg6_pernet_data *seg6_data;

	seg6_data = seg6_pernet(net);

	return &(seg6_data->seg6_local_data);
}
EXPORT_SYMBOL(seg6_local_pernet);

/*$Andrea */
inline bool seg6_local_varattrs_mask_eq(struct seg6_local_lwt *slwt,
		unsigned long mask)
{
	return (slwt->varattrs == mask);
}

/*
 * $Andrea
 * Function used for comparing spinfo_key objects.
 */
static int seg6_local_spinfo_key_cmpfn(struct rhashtable_compare_arg *arg,
				       const void *obj)
{
	const struct seg6_local_spinfo_key *spinfo_key = obj;

	return spinfo_key->key != *((__u32 *)arg->key);
}

/* $Andrea */
static const struct rhashtable_params spinfo_ht_default_params = {
		.head_offset =
			offsetof(struct seg6_local_spinfo_key, node),
		.key_offset
			= offsetof(struct seg6_local_spinfo_key, key),
		.key_len		= sizeof(u32),
		.automatic_shrinking	= true,
		.obj_cmpfn		= seg6_local_spinfo_key_cmpfn,
};


/* $Andrea */
static inline struct net *fib6_config_get_net(struct fib6_config *fib6_cfg)
{
	struct nl_info *nli = &fib6_cfg->fc_nlinfo;

	return nli->nl_net;
}

/* $Andrea */
static inline void fib6_config_set_dst(struct rt6key *dst,
				       struct fib6_config *fib6_cfg)
{
	ipv6_addr_prefix(&dst->addr, &fib6_cfg->fc_dst, fib6_cfg->fc_dst_len);
	dst->plen = fib6_cfg->fc_dst_len;
}

/* $Andrea */
static inline void fib6_config_set_table_id(u32 *table_id,
					    struct fib6_config *fib6_cfg)
{
	*table_id = fib6_cfg->fc_table;
}

/*
 * $Andrea
 * Returns the rhashtable which contains info for proxy.
 */
static inline struct rhashtable *seg6_local_spinfo_table(struct net *net)
{
	struct seg6_local_pernet_data *seg6_local_data;
	struct seg6_local_spinfo *spinfo;

	seg6_local_data = seg6_local_pernet(net);
	spinfo = &(seg6_local_data->spinfo);

	return &(spinfo->spinfo_ht_key);
}

/* $Andrea */
static inline struct rhashtable_params *seg6_local_spinfo_table_params(
		struct net *net)
{
	struct seg6_local_pernet_data *seg6_local_data;
	struct seg6_local_spinfo *spinfo;

	seg6_local_data = seg6_local_pernet(net);
	spinfo = &(seg6_local_data->spinfo);

	return &(spinfo->spinfo_ht_params);
}

/*
 * $Andrea
 * This function is called at lwt's construction.
 */
static int seg6_local_lwtunnel_build_state(struct seg6_local_lwt *slwt,
		const void *cfg)
{
	int err;
	struct seg6_action_desc *desc;
	int (*lwt_build_state_func)(struct seg6_local_lwt *slwt,
			const void *cfg);


	if (!(desc = slwt->desc))
		return -EINVAL;

	err = 0;
	lwt_build_state_func = desc->slwt_ops.build_state;
	if (lwt_build_state_func)
		err = lwt_build_state_func(slwt, cfg);

	return err;
}

/*
 * $Andrea
 * This function is called at lwt's destruction.
 */
static int seg6_local_lwtunnel_destroy_state(struct seg6_local_lwt *slwt)
{
	int err;
	struct seg6_action_desc *desc;
	int (*lwt_destroy_state_func)(struct seg6_local_lwt *slwt);

	if (!(desc = slwt->desc))
		return -EINVAL;

	err = 0;
	lwt_destroy_state_func = desc->slwt_ops.destroy_state;
	if (lwt_destroy_state_func)
		err = lwt_destroy_state_func(slwt);

	return err;
}

struct seg6_local_lwt *seg6_local_lwtunnel(struct lwtunnel_state *lwt)
{
	return (struct seg6_local_lwt *)lwt->data;
}

struct ipv6_sr_hdr *get_srh(struct sk_buff *skb)
{
	struct ipv6_sr_hdr *srh;
	int len, srhoff = 0;

	if (ipv6_find_hdr(skb, &srhoff, IPPROTO_ROUTING, NULL, NULL) < 0)
		return NULL;

	if (!pskb_may_pull(skb, srhoff + sizeof(*srh)))
		return NULL;

	srh = (struct ipv6_sr_hdr *)(skb->data + srhoff);

	len = (srh->hdrlen + 1) << 3;

	if (!pskb_may_pull(skb, srhoff + len))
		return NULL;

	if (!seg6_validate_srh(srh, len))
		return NULL;

	return srh;
}

struct ipv6_sr_hdr *get_and_validate_srh(struct sk_buff *skb)
{
	struct ipv6_sr_hdr *srh;

	srh = get_srh(skb);
	if (!srh)
		return NULL;

	if (srh->segments_left == 0)
		return NULL;

#ifdef CONFIG_IPV6_SEG6_HMAC
	if (!seg6_hmac_validate_skb(skb))
		return NULL;
#endif

	return srh;
}

bool decap_and_validate(struct sk_buff *skb, int proto)
{
	struct ipv6_sr_hdr *srh;
	unsigned int off = 0;

	srh = get_srh(skb);
	if (srh && srh->segments_left > 0)
		return false;

#ifdef CONFIG_IPV6_SEG6_HMAC
	if (srh && !seg6_hmac_validate_skb(skb))
		return false;
#endif

	if (ipv6_find_hdr(skb, &off, proto, NULL, NULL) < 0)
		return false;

	if (!pskb_pull(skb, off))
		return false;

	skb_postpull_rcsum(skb, skb_network_header(skb), off);

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb->encapsulation = 0;

	return true;
}

static void advance_nextseg(struct ipv6_sr_hdr *srh, struct in6_addr *daddr)
{
	struct in6_addr *addr;

	srh->segments_left--;
	addr = srh->segments + srh->segments_left;
	*daddr = *addr;
}

static void lookup_nexthop(struct sk_buff *skb, struct in6_addr *nhaddr,
			   u32 tbl_id)
{
	struct net *net = dev_net(skb->dev);
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	int flags = RT6_LOOKUP_F_HAS_SADDR;
	struct dst_entry *dst = NULL;
	struct rt6_info *rt;
	struct flowi6 fl6;

	fl6.flowi6_iif = skb->dev->ifindex;
	fl6.daddr = nhaddr ? *nhaddr : hdr->daddr;
	fl6.saddr = hdr->saddr;
	fl6.flowlabel = ip6_flowinfo(hdr);
	fl6.flowi6_mark = skb->mark;
	fl6.flowi6_proto = hdr->nexthdr;

	if (nhaddr)
		fl6.flowi6_flags = FLOWI_FLAG_KNOWN_NH;

	if (!tbl_id) {
		dst = ip6_route_input_lookup(net, skb->dev, &fl6, flags);
	} else {
		struct fib6_table *table;

		table = fib6_get_table(net, tbl_id);
		if (!table)
			goto out;

		rt = ip6_pol_route(net, table, 0, &fl6, flags);
		dst = &rt->dst;
	}

	if (dst && dst->dev->flags & IFF_LOOPBACK && !dst->error) {
		dst_release(dst);
		dst = NULL;
	}

out:
	if (!dst) {
		rt = net->ipv6.ip6_blk_hole_entry;
		dst = &rt->dst;
		dst_hold(dst);
	}

	skb_dst_drop(skb);
	skb_dst_set(skb, dst);
}

/* regular endpoint function */
static int input_action_end(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);

	lookup_nexthop(skb, NULL, 0);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* regular endpoint, and forward to specified nexthop */
static int input_action_end_x(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);

	lookup_nexthop(skb, &slwt->nh6, 0);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_t(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);

	lookup_nexthop(skb, NULL, slwt->table);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* decapsulate and forward inner L2 frame on specified interface */
static int input_action_end_dx2(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	struct net *net = dev_net(skb->dev);
	struct net_device *odev;
	struct ethhdr *eth;

	if (!decap_and_validate(skb, NEXTHDR_NONE))
		goto drop;

	if (!pskb_may_pull(skb, ETH_HLEN))
		goto drop;

	skb_reset_mac_header(skb);
	eth = (struct ethhdr *)skb->data;

	/* To determine the frame's protocol, we assume it is 802.3. This avoids
	 * a call to eth_type_trans(), which is not really relevant for our
	 * use case.
	 */
	if (!eth_proto_is_802_3(eth->h_proto))
		goto drop;

	odev = dev_get_by_index_rcu(net, slwt->oif);
	if (!odev)
		goto drop;

	/* As we accept Ethernet frames, make sure the egress device is of
	 * the correct type.
	 */
	if (odev->type != ARPHRD_ETHER)
		goto drop;

	if (!(odev->flags & IFF_UP) || !netif_carrier_ok(odev))
		goto drop;

	skb_orphan(skb);

	if (skb_warn_if_lro(skb))
		goto drop;

	skb_forward_csum(skb);

	if (skb->len - ETH_HLEN > odev->mtu)
		goto drop;

	skb->dev = odev;
	skb->protocol = eth->h_proto;

	return dev_queue_xmit(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* decapsulate and forward to specified nexthop */
static int input_action_end_dx6(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	struct in6_addr *nhaddr = NULL;

	/* this function accepts IPv6 encapsulated packets, with either
	 * an SRH with SL=0, or no SRH.
	 */

	if (!decap_and_validate(skb, IPPROTO_IPV6))
		goto drop;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		goto drop;

	/* The inner packet is not associated to any local interface,
	 * so we do not call netif_rx().
	 *
	 * If slwt->nh6 is set to ::, then lookup the nexthop for the
	 * inner packet's DA. Otherwise, use the specified nexthop.
	 */

	if (!ipv6_addr_any(&slwt->nh6))
		nhaddr = &slwt->nh6;

	lookup_nexthop(skb, nhaddr, 0);

	return dst_input(skb);
drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_dx4(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	struct iphdr *iph;
	__be32 nhaddr;
	int err;

	if (!decap_and_validate(skb, IPPROTO_IPIP))
		goto drop;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto drop;

	skb->protocol = htons(ETH_P_IP);

	iph = ip_hdr(skb);

	nhaddr = slwt->nh4.s_addr ?: iph->daddr;

	skb_dst_drop(skb);

	err = ip_route_input(skb, nhaddr, iph->saddr, 0, skb->dev);
	if (err)
		goto drop;

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int input_action_end_dt6(struct sk_buff *skb,
				struct seg6_local_lwt *slwt)
{
	if (!decap_and_validate(skb, IPPROTO_IPV6))
		goto drop;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		goto drop;

	lookup_nexthop(skb, NULL, slwt->table);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* push an SRH on top of the current one */
static int input_action_end_b6(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	int err = -EINVAL;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	err = seg6_do_srh_inline(skb, slwt->srh);
	if (err)
		goto drop;

	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	lookup_nexthop(skb, NULL, 0);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return err;
}

/* encapsulate within an outer IPv6 header and a specified SRH */
static int input_action_end_b6_encap(struct sk_buff *skb,
				     struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	int err = -EINVAL;

	srh = get_and_validate_srh(skb);
	if (!srh)
		goto drop;

	advance_nextseg(srh, &ipv6_hdr(skb)->daddr);

	skb_reset_inner_headers(skb);
	skb->encapsulation = 1;

	err = seg6_do_srh_encap(skb, slwt->srh, IPPROTO_IPV6);
	if (err)
		goto drop;

	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	lookup_nexthop(skb, NULL, 0);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return err;
}


/* $Andrea @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ */

/*
 * Allocates spinfo_data structure and initializes it.
 */
static struct seg6_local_spinfo_data *seg6_local_spinfo_data_alloc(
		unsigned long ipv6_sr_hdr_len)
{
	struct seg6_local_spinfo_data *spinfo_data;
	struct seg6_local_spinfo_header *spinfo_header;
	struct ipv6_sr_hdr *ipv6_sr_hdr;
	struct ipv6hdr *ipv6_hdr;
	int cache_err;

	spinfo_data = kzalloc(sizeof(*spinfo_data), GFP_ATOMIC);
	if (!spinfo_data)
		return NULL;

	ipv6_hdr = kzalloc(sizeof(struct ipv6hdr), GFP_ATOMIC);
	if (!ipv6_hdr)
		goto free_spinfo_data;

	ipv6_sr_hdr = kzalloc(ipv6_sr_hdr_len, GFP_ATOMIC);
	if (!ipv6_sr_hdr)
		goto free_ipv6_hdr;

	cache_err = dst_cache_init(&spinfo_data->cache, GFP_ATOMIC);
	if (cache_err)
		goto free_srv6_hdr;

	spinfo_header = &spinfo_data->hdr;
	spinfo_header->ipv6_hdr = ipv6_hdr;
	spinfo_header->ipv6_sr_hdr = ipv6_sr_hdr;

	return spinfo_data;

free_srv6_hdr:
	kfree(ipv6_sr_hdr);

free_ipv6_hdr:
	kfree(ipv6_hdr);

free_spinfo_data:
	kfree(spinfo_data);

	return NULL;
}

static void seg6_local_spinfo_data_free(
		struct seg6_local_spinfo_data *spinfo_data)
{
	struct seg6_local_spinfo_header *spinfo_header;
	struct ipv6_sr_hdr *ipv6_sr_hdr;
	struct ipv6hdr *ipv6_hdr;

	if (!spinfo_data)
		return;

	dst_cache_destroy(&spinfo_data->cache);

	spinfo_header = &spinfo_data->hdr;
	ipv6_hdr = spinfo_header->ipv6_hdr;
	ipv6_sr_hdr = spinfo_header->ipv6_sr_hdr;

	if (ipv6_sr_hdr)
		kfree(ipv6_sr_hdr);

	if (ipv6_hdr)
		kfree(ipv6_hdr);

	kfree(spinfo_data);

	//pr_debug("seg6_local_spinfo_data_free called and executed for %p.\n",
	//		spinfo_data);
}

/*
 *  Free spinfo_data which points to this @rcu param. This is used as a
 *  callback's clean up function and it is executed as soon as any reader
 *  which was refererring to @rcu has exited rcu lock/unlock critical section.
 */
static void seg6_local_spinfo_data_free_rcu(struct rcu_head *rcu)
{
	struct seg6_local_spinfo_data *spinfo_data;

	spinfo_data = (struct seg6_local_spinfo_data *) container_of(rcu,
			struct seg6_local_spinfo_data, rcu);
	if (spinfo_data)
		seg6_local_spinfo_data_free(spinfo_data);
}

/*
 * Evaluates ipv6_hdr_sr packet length.
 */
static inline int ipv6_sr_len(struct ipv6_sr_hdr *ipv6_sr_hdr)
{
	return ((ipv6_sr_hdr->hdrlen + 1) << 3);
}

/**
 * Publishes a new spinfo_data for the key to which it belongs to.
 * Returns the old spinfo_data if it was present or NULL if spinfo_data
 * was not intialized yet. Otherwise return PTR_ERR error.
 *
 * It must be called with rcu_read_lock() and with a lock on the spinfo_key.
 *
 */
static struct seg6_local_spinfo_data *seg6_local_spinfo_data_publish(
		struct seg6_local_spinfo_key *spinfo_key,
		struct seg6_local_spinfo_header *src, int timeout)
{
	struct seg6_local_spinfo_data *spinfo_data_new, *spinfo_data_old;
	struct seg6_local_spinfo_header *dst;
	int srv6_hdr_len;

	srv6_hdr_len = ipv6_sr_len(src->ipv6_sr_hdr);

	spinfo_data_new = seg6_local_spinfo_data_alloc(srv6_hdr_len);
	if (unlikely(!spinfo_data_new))
		return ERR_PTR(-ENOMEM);

	/* We copy the spinfo_header inside the new spinfo_data */
	dst = &spinfo_data_new->hdr;
	memcpy(dst->ipv6_hdr, src->ipv6_hdr, sizeof(struct ipv6hdr));
	memcpy(dst->ipv6_sr_hdr, src->ipv6_sr_hdr, srv6_hdr_len);

	/* We convert timeout which is expressed in secs to jiffies */
	spinfo_data_new->aging_jiffies = get_jiffies_64() + (timeout * HZ);

	//pr_debug("seg6_local_spinfo_data_publish: new aging %llu\n",
	//		spinfo_data_new->aging_jiffies);

	spinfo_data_old = rcu_dereference_check(spinfo_key->data,
			spin_is_locked(&spinfo_key->lock));
	/*
	 * Now it's time to publish the update, and after grace period
	 * we can destroy old data (nobody is referencing to spinfo_data_old
	 * after that period).
	 */
	rcu_assign_pointer(spinfo_key->data, spinfo_data_new);

	return spinfo_data_old;
}

/*
 * Allocates new seg6_local_spinfo_key and initialize its fields.
 */
static struct seg6_local_spinfo_key *seg6_local_spinfo_key_alloc(void)
{
	struct seg6_local_spinfo_key *spinfo_key;

	spinfo_key = kzalloc(sizeof(*spinfo_key), GFP_ATOMIC);
	if (!spinfo_key)
		return NULL;

	spin_lock_init(&spinfo_key->lock);
	spinfo_key->state = SEG6_LOCAL_SPINFO_KEY_VALID;

	return spinfo_key;
}

static void seg6_local_spinfo_key_free(struct seg6_local_spinfo_key *spinfo_key)
{
	struct seg6_local_spinfo_data *spinfo_data;

	if (!spinfo_key)
		return;

	spinfo_data = spinfo_key->data;
	if (spinfo_data)
		seg6_local_spinfo_data_free(spinfo_data);

	kfree(spinfo_key);

	//pr_debug("seg6_local_spinfo_key_free called and executed.\n");
}

static void seg6_local_spinfo_key_free_rcu(struct rcu_head *rcu)
{
	struct seg6_local_spinfo_key *spinfo_key;

	spinfo_key = (struct seg6_local_spinfo_key *) container_of(rcu,
			struct seg6_local_spinfo_key, rcu);

	if (spinfo_key)
		seg6_local_spinfo_key_free(spinfo_key);
}

/*
 * Tries to update spinfo_key with new spinfo_data if the previous one is
 * obsolete.
 *
 * Needs to be called with rcu lock held.
 */
static int seg6_local_spinfo_data_update(
		struct seg6_local_spinfo_key *spinfo_key,
		struct seg6_local_spinfo_header *spinfo_hdr, int timeout)

{
	struct seg6_local_spinfo_data *spinfo_data;
	int ret;

	ret = 0;
	spinfo_data = rcu_dereference(spinfo_key->data);
	if (likely(spinfo_data)) {
		if (likely(time_is_after_eq_jiffies64(
					spinfo_data->aging_jiffies))) {
			//pr_debug("seg6_local_spinfo_data_update: no timeout.\n");

			goto fast_path;
		}
	}

	//pr_debug("seg6_local_spinfo_data_update: first initialization.\n");

	if (!spin_trylock_bh(&spinfo_key->lock))
		goto fast_path;

	/**
	 * Lock acquired, so this is the slow-path.
	 * Here we are if 1) spinfo_data is NULL or 2) is expired.
	 */
	switch(spinfo_key->state) {
		case SEG6_LOCAL_SPINFO_KEY_INVALID:
			/* Invalid key; it will be freed as soon as possible. */
			spinfo_data = ERR_PTR(-EINVAL);
		break;

		case SEG6_LOCAL_SPINFO_KEY_VALID:
			//pr_debug("seg6_local_spinfo_data_update: timeout EXPIRED.\n");

			/**
			 * We need to read again the spinfo_data pointer because
			 * of it may be changed (previous reading was outside
			 * mutual exclusion context). We want to free only data
			 * that will not be reachable by anyone.
			 */
			spinfo_data = seg6_local_spinfo_data_publish(
					spinfo_key, spinfo_hdr, timeout);

			break;

		default:
			/* We should not be here ... */
			BUG();
		break;
	}

	spin_unlock_bh(&spinfo_key->lock);
	/* Lock released. */

	if (unlikely(IS_ERR_OR_NULL(spinfo_data))) {
		ret = PTR_ERR(spinfo_data);
	} else {
		/* Here we are with no errors and spinfo_data != NULL. */
		call_rcu(&spinfo_data->rcu,
				seg6_local_spinfo_data_free_rcu);

		//pr_debug("seg6_local_spinfo_data_free_rcu call_rcu registered"
		//		" for %p.\n", spinfo_data);
	}

fast_path:
	//pr_debug("seg6_local_spinfo_data_update returns %d\n", ret);

	return ret;
}

/*
 * Unregisters the key.
 *
 * Returns 0 if succeeds, ERROR < 0 otherwise.
 * It can be called from softirq context.
 */
static int seg6_local_spinfo_key_unregister(struct net *net, const u32 key)
{
	struct seg6_local_spinfo_data *spinfo_data;
	struct seg6_local_spinfo_key *spinfo_key;
	struct rhashtable_params *ht_params;
	struct rhashtable *ht;
	int err;

	err = -ENOENT;
	spinfo_data = NULL;

	ht = seg6_local_spinfo_table(net);
	ht_params = seg6_local_spinfo_table_params(net);

	rcu_read_lock();

	spinfo_key = (struct seg6_local_spinfo_key *)
		rhashtable_lookup(ht, (u32 *) &key, *ht_params);
	if (!spinfo_key)
		goto fast_path;

	/**
	 * We grab the lock to avoid race condition with softirq
	 * spinfo_data update. Everytime a spinfo_data is expired then
	 * the update-side creates a new spinfo_data and replaces the previous
	 * pointer with the new one.
	 */
	spin_lock_bh(&spinfo_key->lock);

	switch(spinfo_key->state) {
		case SEG6_LOCAL_SPINFO_KEY_INVALID:
			/* Key is already marked as invalid. */
			err = -EINVAL;
		break;

		case SEG6_LOCAL_SPINFO_KEY_VALID:
			WRITE_ONCE(spinfo_key->state,
					SEG6_LOCAL_SPINFO_KEY_INVALID);

			err = rhashtable_remove_fast(ht, &spinfo_key->node,
					*ht_params);
			WARN_ON(err);
		break;

		default:
			BUG();
		break;
	}

	spin_unlock_bh(&spinfo_key->lock);

	/**
	 * Now it's time to register rcu_callback for destroying the spinfo_key
	 * as soon as it will be not referenced anymore.
	 */
	if (!err)
		call_rcu(&spinfo_key->rcu, seg6_local_spinfo_key_free_rcu);

fast_path:
	rcu_read_unlock();

	return err;
}

/*
 * Creates a new @seg6_local_spinfo_key and it initializes the
 * fields of the structure with params taken from @slwt and @cfg.
 * Returns the key or NULL in case of error.
 */
static struct seg6_local_spinfo_key *seg6_local_spinfo_key_init(
		struct net *net, struct seg6_local_lwt *slwt, void *cfg)
{
	struct seg6_local_spinfo_key *spinfo_key;

	spinfo_key = seg6_local_spinfo_key_alloc();
	if (unlikely(!spinfo_key))
		return NULL;

	//pr_debug("seg6_local_spinfo_key_init: spinfo_key allocated.\n");

	/* Here we initialize key's info */
	spinfo_key->key = slwt->oif;
	fib6_config_set_dst(&spinfo_key->sid, (struct fib6_config *) cfg);
	fib6_config_set_table_id(&spinfo_key->table_id,
			(struct fib6_config *) cfg);

	return spinfo_key;
}

/*
 * Stores the given key @spinfo_key and returns the NULL if registration
 * process was successfull, the pointer to the key if it was already
 * registered, and ERR_PTR otherwise.
 *
 * It can be called within atomic context.
 */
static struct seg6_local_spinfo_key *seg6_local_spinfo_key_register(
		struct net *net, struct seg6_local_spinfo_key *spinfo_key,
		bool *const key_owner)
{
	struct seg6_local_spinfo_key *stored_spinfo_key;
	struct rhashtable_params *ht_params;
	struct rhashtable *ht;

	ht = seg6_local_spinfo_table(net);
	ht_params = seg6_local_spinfo_table_params(net);

	/*
	 * If key_owner is specified we set its value to false before taking
	 * any action. In this way the parameter will be always in a
	 * consistent state with respect to the following operations.
	 */
	if (key_owner)
		*key_owner = false;

	/* We try to insert the spinfo_key we check for  the returned item. */
	stored_spinfo_key = (struct seg6_local_spinfo_key *)
				rhashtable_lookup_get_insert_fast(
					ht, &spinfo_key->node, *ht_params);

	//pr_debug("seg6_local_spinfo_key_register: "
	//		"rhashtable_lookup_get_insert_fast() returns: %p\n",
	//		stored_spinfo_key);

	if (likely(!stored_spinfo_key)) {
		//pr_debug("seg6_local_spinfo_key_register: key has been successfully "
		//		"stored: %p\n", spinfo_key);

		/* We notify to the owner that its key has been registerd */
		if (key_owner)
			*key_owner = true;

		return NULL;
	}

	/* Here we are if 1) an error occurred or 2) the key already exists */
	return stored_spinfo_key;
}

/*
 * Sets the key for the given @slwt
 *
 * Returns 0 in case of success, < 0 otherwise.
 */
static int seg6_local_spinfo_key_setup(
		struct net *net, struct seg6_local_lwt *slwt,
		void *cfg, bool *const key_owner)
{
	struct seg6_local_spinfo_key *spinfo_key, *stored_spinfo_key;

	spinfo_key = seg6_local_spinfo_key_init(net, slwt, cfg);
	if (unlikely(!spinfo_key))
		return -ENOMEM;

	/* We store the key and check the result */
	stored_spinfo_key = seg6_local_spinfo_key_register(net,
						spinfo_key, key_owner);
	if (likely(!stored_spinfo_key))
		goto out;

	/* stored_spinfo_key is != NULL, so we can destroy the spinfo_key */
	seg6_local_spinfo_key_free(spinfo_key);

	if (!IS_ERR(stored_spinfo_key)) {
		//pr_debug("seg6_local_spinfo_key_setup: key already exists %p\n",
		//		stored_spinfo_key);

		goto out;
	}

	/*
	 * An error is occurred during key registration, so we need to return
	 * the error to the caller.
	 */
	return PTR_ERR(stored_spinfo_key);

out:
	return 0;
}

/*
 * Retrieves seg6_local_spinfo_key object that matches @ifindex key.
 *
 * Return seg6_local_spinfo_key object's pointer or NULL.
 * This function must be called with rcu_read_lock held.
 */
static inline struct seg6_local_spinfo_key *seg6_local_spinfo_key_lookup(
		struct net *net, int ifindex)
{
	struct rhashtable_params *ht_params;
	struct rhashtable *ht;

	ht = seg6_local_spinfo_table(net);
	ht_params = seg6_local_spinfo_table_params(net);

	return rhashtable_lookup(ht, (u32 *) &ifindex, *ht_params);
}

/*
 * Tries to find the suitable header using given @net and @oif. @oif and @net
 * are used as a compound key to identify the header @seg_local_spinfo_header.
 * If there is no entry for @oif then this function returns -ENOENT; otherwise
 * the procedure tries to store the @spinfo_hdr (for the given key) only if
 * the header is expired.
 *
 * Static proxy info:
 *	1) Key:		interface oif and net
 *	2) Data:	outer IPv6 and SRv6 headers (spinfo_header).
 */
static int seg6_local_spinfo_header_handler(struct net *net, int oif,
		struct seg6_local_spinfo_header *spinfo_hdr,
		int timeout)
{
	struct seg6_local_spinfo_key *spinfo_key;
	int err = -ENOENT;

	//pr_debug("enter handler called.\n");

	rcu_read_lock();

	spinfo_key = seg6_local_spinfo_key_lookup(net, oif);
	if (unlikely(!spinfo_key))
		goto out;

	//pr_debug("spinfo_key after lookup value: %p\n", spinfo_key);

	/* Update spinfo_data w.r.t. the given key */
	err = seg6_local_spinfo_data_update(spinfo_key, spinfo_hdr, timeout);

out:
	rcu_read_unlock();

	//pr_debug("exit handler called, result value %d\n", err);

	return err;
}

static void seg6_local_spinfo_key_free_hi(void *ptr, void *arg)
{
	struct seg6_local_spinfo_key *spinfo_key =
		(struct seg6_local_spinfo_key *) ptr;
	/* Unused param. */
	(void)(arg);

	if (spinfo_key)
		call_rcu(&spinfo_key->rcu, seg6_local_spinfo_key_free_rcu);
}

/*
 * @slwt: seg6_local_lwt tunnel
 *
 * Returns the nexthop address protocol used to forward outcoming packets for
 * the given @slwt tunnel.
 */
static inline int seg6_local_nh_addr_proto(struct seg6_local_lwt *slwt)
{
	struct seg6_action_desc *desc;
	unsigned long varattrs;
	int i, proto, proto_ok;

	desc = slwt->desc;
	varattrs = slwt->varattrs;
	proto = NH_PROTO_UNSPEC;
	proto_ok = 0;

	for(i = 1; i < NH_PROTO_MAX + 1; ++i) {
		if (varattrs & (1 << nh_protos[i])) {
			proto = i;
			++proto_ok;
		}
	}

	/* Only one nexthop protocol is allowed. */
	if (proto_ok > 1)
		return NH_PROTO_INVALID;

	return proto;
}

/*
 * This function checks for correctness of varattrs.
 */
static bool check_end_ad_varattrs(struct seg6_local_lwt *slwt)
{
	/*
	 * Only one nexthop proto can be specified so we remove from the
	 * NH flags from the mask.
	 * We test each possibile configuration for the nexthop; that's a quick
	 * and dirty solution but the number of configurations is very limited.
	 */
	if (seg6_local_varattrs_mask_eq(slwt, (1 << SEG6_LOCAL_NH6)))
		return true;

	if (seg6_local_varattrs_mask_eq(slwt, (1 << SEG6_LOCAL_NHETH)))
		return true;

	/* For any invalid configuration we return false */
	return false;
}

/*
 * This function is called on seg6_local_lwt's (End.AD) creation.
 */
static int seg6_local_end_ad_build_state(struct seg6_local_lwt *slwt,
		const void *cfg)
{
	struct fib6_config *fib6_cfg = (struct fib6_config *) cfg;
	struct net *net;
	int nh_proto, err;

	//pr_debug("seg6_local_end_ad_build_state: unified north/south bound\n");

	net = fib6_config_get_net(fib6_cfg);
	if (!net)
		return -ENODEV;

	/* We verify the varattrs for the End.AD behaviour */
	if (!check_end_ad_varattrs(slwt))
		return -EINVAL;

	/* Loopback interface is not allowed here */
	if (slwt->oif <= LOOPBACK_IFINDEX)
		return -EINVAL;

	/* We check and parse nh protocol */
	nh_proto = seg6_local_nh_addr_proto(slwt);
	if (nh_proto <= 0)
		return -EINVAL;

	/* We set the nexthop protocol (eth or ipv6) */
	slwt->nh_proto = nh_proto;

	/* Key setup */
	err = seg6_local_spinfo_key_setup(net, slwt, fib6_cfg, NULL);
	if (err < 0)
		return err;

	/* We store net (ns) ptr into private_data for further access. */
	slwt->private_data = (void *) net;

	return 0;
}

/*
 * This function is called on seg6_local_lwt's (End.AD) destruction.
 */
static int seg6_local_end_ad_destroy_state(struct seg6_local_lwt *slwt)
{
	struct net *net;

	//pr_debug("seg6_local_end_ad_destroy_state: unified north/south bound\n");

	net = (struct net *) slwt->private_data;
	if (!net)
		return -ENODEV;

	/* Destroy the key and its own data, if any */
	return seg6_local_spinfo_key_unregister(net, slwt->oif);
}

static inline void seg6_local_spinfo_header_set(
		struct seg6_local_spinfo_header *const spinfo_hdr,
		struct ipv6hdr *ipv6_hdr,
		struct ipv6_sr_hdr *ipv6_sr_hdr)
{
	spinfo_hdr->ipv6_hdr = ipv6_hdr;
	spinfo_hdr->ipv6_sr_hdr = ipv6_sr_hdr;
}

/*
 * This function differs from the David's one because of we do not perform
 * any validation about srv6 or seg6_hmac.
 */
static bool decapsulate(struct sk_buff *skb, int proto)
{
	unsigned int off = 0;

	if (ipv6_find_hdr(skb, &off, proto, NULL, NULL) < 0)
		return false;

	if (!pskb_pull(skb, off))
		return false;

	skb_postpull_rcsum(skb, skb_network_header(skb), off);

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb->encapsulation = 0;

	return true;
}

/*
 * NOTICE: we suppose to have IPV6 in IPV6 encapsulation.
 */
static int seg6_local_encap_and_copy_spinfo_header(struct sk_buff *skb,
		struct seg6_local_spinfo_header *spinfo_hdr)
{
	int tot_len, headroom_mac_len, ipv6_sr_hdr_len;
	struct ipv6_sr_hdr *ipv6_sr_hdr;
	struct ipv6hdr *ipv6_hdr_outer;
	int err;

	/* We suppose that srv6 and ipv6 headers have already been validated. */
	skb_reset_inner_headers(skb);
	skb->encapsulation = 1;

	headroom_mac_len = 0;
	ipv6_sr_hdr_len = ipv6_sr_len(spinfo_hdr->ipv6_sr_hdr);
	tot_len = sizeof(struct ipv6hdr) + ipv6_sr_hdr_len;

	if (likely(skb_mac_header_was_set(skb)))
		headroom_mac_len = skb->mac_len;

	err = skb_cow_head(skb, tot_len + headroom_mac_len);
	if (unlikely(err)) {
		//pr_debug("skb_cow_head() returns with error: %d\n", err);

		return err;
	}

	/* We copy back srv6 header and ipv6 outer header */
	ipv6_sr_hdr = skb_push(skb, ipv6_sr_hdr_len);
	memcpy(ipv6_sr_hdr,  spinfo_hdr->ipv6_sr_hdr, ipv6_sr_hdr_len);
	ipv6_hdr_outer = skb_push(skb, sizeof(struct ipv6hdr));
	memcpy(ipv6_hdr_outer,spinfo_hdr->ipv6_hdr, sizeof(struct ipv6hdr));

	skb_reset_network_header(skb);

	/*
	 * We rebuild the mac address but at this point DA and SA are swapped.
	 * We don't need to care about this because of the packet must still
	 * be routed (and hence SA and DA will be resolved at that point).
	 * */
	skb_mac_header_rebuild(skb);

	ipv6_hdr_outer->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	return 0;
}

/*
 * Northbound's output function.
 *
 * @skb:  packet that has to be sent
 * @odev: the output interface
 * @slwt: tunnel used by the End.AD behaviour.
 *
 * This function needs to be called with the reference count of odev held.
 * This function must be called only from softirq context.
 */
static int end_ad_northbound_output(struct sk_buff *skb,
		struct net_device *odev, struct seg6_local_lwt *slwt)
{
	struct neighbour *neigh;
	int ret = -EINVAL;

	/* We are preparing the packet that has to be sent. */
	skb->pkt_type = PACKET_OUTGOING;
	skb->dev = odev;

	/*
	 * We drop the reference to @skb->dst_entry if any;
	 * this is a decapsulated packet and hence @skb->dst_entry is in
	 * the most of cases wrong. A wrong dst_entry causes throubles during
	 * ND solecitation operation.
	 */
	skb_dst_drop(skb);

	switch(slwt->nh_proto) {
		case NH_PROTO_ETH:
			if (unlikely(odev->type != ARPHRD_ETHER))
				goto out;

			if (unlikely(!(odev->flags & IFF_UP) ||
						!netif_carrier_ok(odev)))
				goto out;

			skb_orphan(skb);

			if (unlikely(skb_warn_if_lro(skb)))
				goto out;

			/* XXX: do we need to check for odev->mtu size ? */

			/* See /opt/linux/linux-4.14/net/ethernet/eth.c */
			ret = dev_hard_header(skb, skb->dev, ETH_P_IPV6,
					slwt->nheth, NULL, skb->len);
			if (unlikely(ret < 0)) {
				//pr_debug("dev_hard_header error\n");

				ret = -ENXIO;
				goto out;
			}

			/*
			 * We are ready to send the packet through the network
			 * using the outgoing interface.
			 */
			ret = dev_queue_xmit(skb);
			if (unlikely(NET_XMIT_SUCCESS != ret)) {
				//pr_debug("dev_queue_xmit"
				//		" returns with code: %d\n", ret);
			}

			break;

		case NH_PROTO_IPV6:
			/*
			 * see ip6_output.c: ip6_finish_output2().
			 *
			 * However, we are in a softirq context so _bh() is not
			 * usefull and it may be replaced with
			 * rcu_read_lock() and rcu_read_unlock() variants.
			 */
			rcu_read_lock_bh();
			neigh = __ipv6_neigh_lookup_noref(skb->dev, &slwt->nh6);
			if (unlikely(!neigh))
				neigh = __neigh_create(&nd_tbl, &slwt->nh6,
						skb->dev, false);

			if (likely(!IS_ERR_OR_NULL(neigh))) {
				sock_confirm_neigh(skb, neigh);
				ret = neigh_output(neigh, skb);
				rcu_read_unlock_bh();
			} else {
				rcu_read_unlock_bh();
				ret = (!neigh) ? -EINVAL : PTR_ERR(neigh);

				//pr_debug("neigh creation returns with code: %d\n",
				//		ret);
			}
			break;

		default:
			//pr_debug("unsupported nexthop protocol\n");

			ret = -EOPNOTSUPP;
			break;
	}

out:
	return ret;
}

/*
 * End.AD NORTHBOUND
 *
 * Do not call outside softirq context.
 */
int end_ad_northbound(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct net *net = dev_net(skb->dev);
	struct net_device *odev;
	struct ipv6_sr_hdr *srh;
	struct ipv6hdr *ipv6_hdr_outer;
	struct seg6_local_spinfo_header spinfo_hdr;
	int oif;
	int ret = -EINVAL;

	//pr_debug("End.AD northbound\n");

	if (unlikely(!net_eq(net, (struct net *) slwt->private_data))) {
		ret = -EXDEV;
		goto drop;
	}

	/*
	 * Here we check if the current packet conatins a valid srv6 header.
	 */
	srh = get_srh(skb);
	if (unlikely(!srh)) {
		//pr_debug("no valid SRv6 header found, packet will be dropped\n");

		ret = -ENXIO;
		goto drop;
	}

	/*
	 * We retrieve the chain from the lwtunnel's state.
	 * We need to retrieve net_device which has been specified in the chian.
	 *
	 * NOTICE: any time we grab the net_device we need also to release it
	 * on exit (only in case where dev_get_* completes without any error).
	 *
	 */
	oif = slwt->oif;
	odev = dev_get_by_index(net, oif);
	if (unlikely(!odev)) {
		//pr_debug("oif %d not found; packet will be dropped\n", oif);

		ret = -ENODEV;
		goto drop;
	}

	/*
	 * We grab the reference to the header of outer ipv6 packet.
	 * We have to discard the packet if hop_limit is <= 1.
	 *
	 * NOTICE: From now on, any time we want to exit from the main path
	 * we have to jump to release_and_drop label. That is mandatory because
	 * of we have to free odev reference counter (which has previously
	 * taken by calling dev_get_by_index()).
	 */
	ipv6_hdr_outer = ipv6_hdr(skb);

	if  (unlikely(0 >= srh->segments_left)) {
		/* for segments_left == 0 we have to discard the* packet. */
		//pr_debug("packet will be dropped due to segments_left == 0\n");

		ret = -EPERM;
		goto release_and_drop;
	}
	if (unlikely(1 >= ipv6_hdr_outer->hop_limit)) {
		//pr_debug("packet will be dropped due to hop_limit <= 1\n");

		ret = -EPERM;
		goto release_and_drop;
	}

	/* We decrease hop_limit and we select next segment. */
	--ipv6_hdr_outer->hop_limit;
	advance_nextseg(srh, &ipv6_hdr_outer->daddr);

	/*
	 * Here is where the magic happens: ipv6 outer and srv6 headers are
	 * used to initialize spinfo_hdr structure (using pointers).
	 * This structure is passed to seg6_local_spinfo_header_handler along with
	 * net and ifindex. If there will be a key == oif in the
	 * hashtable then spinfo_hdr may will be copied and used for
	 * encapsulation in southbound.
	 */
	seg6_local_spinfo_header_set(&spinfo_hdr, ipv6_hdr_outer, srh);

	ret = seg6_local_spinfo_header_handler(net, oif, &spinfo_hdr,
			slwt->timeout);
	if (unlikely(ret)) {
		//pr_debug("proxy handler failed with return code: %d\n", ret);

		goto release_and_drop;
	}

	/*
	 * It's time to decapsulate the packet removing all outer headers
	 * until we reached inner IPv6 packet.
	 */
	if (unlikely(!decapsulate(skb, IPPROTO_IPV6))) {
		//pr_debug("error during packet decapsulation\n");

		ret = -ENXIO;
		goto release_and_drop;
	}

	skb_forward_csum(skb);

	/* Packet forwarding to the nexthop */
	ret = end_ad_northbound_output(skb, odev, slwt);
	if (unlikely(ret))
		goto release_and_drop;

	/* Decreasing odev's reference counter */
	dev_put(odev);

	return ret;

release_and_drop:
	/* Decreasing odev's reference counter */
	dev_put(odev);

drop:
	//pr_debug("end_ad_northbound: packet dropped\n");

	kfree_skb(skb);
	return ret;
}

/*
 * This function must be called with RCU lock held.
 */
static struct seg6_local_spinfo_header
	*seg6_local_spinfo_header_get_by_net_and_iif(
			struct net *net, const int iif)
{
	struct seg6_local_spinfo_header *spinfo_hdr;
	struct seg6_local_spinfo_data *spinfo_data;
	struct seg6_local_spinfo_key *spinfo_key;

	spinfo_key = seg6_local_spinfo_key_lookup(net, iif);
	if (unlikely(!spinfo_key)) {
		spinfo_hdr = ERR_PTR(-ENOENT);
		goto out;
	}

	//pr_debug("spinfo_key after lookup value: %p\n", spinfo_key);

	spinfo_data = rcu_dereference(spinfo_key->data);
	if (unlikely(!spinfo_data)) {
		/*
		 * data not available, so we return NULL instead of
		 * an explicit error code.
		 */
		spinfo_hdr = NULL;
		goto out;
	}

	/*
	 * We want valid spinfo_hdr, so data must be valid first. For avoiding
	 * stale data we can use the aging_jiffies value.
	 */
	if (!time_is_after_eq_jiffies64(spinfo_data->aging_jiffies)) {
		//pr_debug("invalid spinfo_data due to timeout expiration\n");

		/* We treat this case as if data was not available. */
		spinfo_hdr = NULL;
		goto out;
	}

	/*
	 * Here we are with spinfo_data != NULL, so we can return the pointer
	 * to the seg6_local_spinfo_header structure.
	 */
	spinfo_hdr = &spinfo_data->hdr;

out:
	return spinfo_hdr;
}



/*
 * End.AD SOUTHBOUND
 *
 * Do not call outside sofitrq context.
 */
int end_ad_southbound(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct net *net = dev_net(skb->dev);
	struct net_device *odev;
	struct seg6_local_spinfo_data *spinfo_data;
	struct seg6_local_spinfo_header *spinfo_hdr;
	struct dst_cache *dst_cache;
	struct dst_entry *dst;
	int iif;
	int ret = -EINVAL;

	//pr_debug("End.AD southbound\n");

	if (unlikely(!net_eq(net, (struct net *) slwt->private_data))) {
		ret = -EXDEV;
		goto drop;
	}

	/*
	 * The ingress interface from which packets reach the southbound.
	 *
	 * NOTE: the iif interface should match with the oif that is used to
	 * deliver packets from the northbound to the VNF. Due to this fact, we
	 * can rid of the explicit iif parameter and use oif directly.
	 */
	iif = slwt->oif;

	rcu_read_lock();

	if (unlikely(!dev_get_by_index_rcu(net, iif))) {
		//pr_debug("iif %d not found; packet will be dropped\n", iif);

		ret = -ENODEV;
		goto release_and_drop;
	}

	/*
	 * We retrieve from the hashtable (per net) the correspondent header
	 * which has been registered (previously) in nortbohund handler.
	 *
	 * NOTICE: if the packet comes from southbound for the first time then
	 * no spinfo_hdr is available and the packet will be dropped.
	 */
	spinfo_hdr = seg6_local_spinfo_header_get_by_net_and_iif(net, iif);
	if (IS_ERR_OR_NULL(spinfo_hdr)) {
		//pr_debug("no valid header has been found for iif %d; "
		//		"packet will be dropped\n", iif);

		ret = -EINVAL;
		goto release_and_drop;
	}

	/*
	 * Here we are with valid data, so we can perform ipv6 in ipv6
	 * encapsulation for the current packet. We restore the outer header
	 * and srv6 header and we don't care to update hop_limit nor
	 * srv6 next_segment. Hop limit will be decrease during forward phase;
	 * srv6 nex_segment has already been decrease during northbound
	 * processing.
	 */
	seg6_local_encap_and_copy_spinfo_header(skb, spinfo_hdr);

	/*
	 * Now the packet is ready to get routed. We need to choose packet
	 * destination and we use ipv6 routing system.
	 *
	 * NOTICE: we change packet's incoming device in order to
	 * fool the routing subsystem and avoiding loops;
	 * Theoretically, we can choose any device except the one where
	 * the packet coming from.
	 * A good candidate for oif interface seems to be the lookpback
	 * inteface.
	 */
	odev = dev_get_by_index_rcu(net, LOOPBACK_IFINDEX);
	if (unlikely(!odev)) {
		 //pr_debug("oif %d not found; packet will be dropped\n",
		 //	LOOPBACK_IFINDEX);

		 ret = -ENODEV;
		 goto release_and_drop;
	}
	skb->dev = odev;

	/* We retrieve dst_entry from cache (dst_cache). */
	spinfo_data = container_of(spinfo_hdr,
			struct seg6_local_spinfo_data, hdr);
	dst_cache = &spinfo_data->cache;

	/*
	 * NOTICE: dst_cache_get & co. require bh disabled; we are executing this
	 * piece of code in softirq context (net_rx).
	 *
	 * dst_cache is for per-cpu; sofitrq net_rx can be executed in parallel
	 * among different cpus. Because of each dst_cache is per cpu, we don't
	 * need to worry about synchronization (each softirq net_rx handler will
	 * access its private copy of dst_cache).
	 */
	dst = dst_cache_get(dst_cache);

	/*
	 * We drop the previous reference to skb->dst if any; in this way GC
	 * could collect unreferenced dst_entry objects.
	 */
	skb_dst_drop(skb);

	if (unlikely(!dst)) {
		lookup_nexthop(skb, NULL, 0);

		dst = skb_dst(skb);
		if (!dst->error) {
			/*
			 * daddr is not used at this time
			 *
			 * NOTICE: dst_cache_set_ip6 takes the reference counter
			 * on the 'dst', so we don't need to care here about that.
			 * As soon as the dst_cache will be destroyed the
			 * reference counter related to 'dst' will be decreased.
			 */
			dst_cache_set_ip6(dst_cache, dst,
					  &ipv6_hdr(skb)->daddr);
		}
	} else {
		skb_dst_set(skb, dst);
	}

	rcu_read_unlock();

	ret = dst_input(skb);
	return ret;

release_and_drop:
	rcu_read_unlock();

drop:
	//pr_debug("packet has been dropped in southbound");

	kfree_skb(skb);
	return ret;
}

/*
 * End.AD entry point.
 */
int end_ad(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	int ifindex;

	//pr_debug("End.AD handler.\n");

	ifindex = skb->dev->ifindex;
	if (ifindex <= LOOPBACK_IFINDEX)
		return -EPERM;

	switch(ifindex ^ slwt->oif) {
		case 0:
			/*
			 * We are receiving the packet on the interface that is
			 * used to send packet from northbound to the VNF. As a
			 * consequence, that interface is the one which is
			 * allowed to receive packet for the southbound's
			 * processing.
			 */
			return end_ad_southbound(skb, slwt);

		default:
			/*
			 * Receiving interface is not registered as an oif
			 * interface for the current End.AD behavioiur. We have
			 * to send packets to the northbound's side.
			 */
			return end_ad_northbound(skb, slwt);
	}

	BUG();
	return 0;
}

/*
 * We use this structure to store/restore the flowi context during the execution
 * of the seg6_local_end_ad_fib_rule_*() operations.
 */
struct seg6_local_end_ad_fib_rule_context {
	struct in6_addr saddr;
	struct in6_addr daddr;
};

/*
 * This function is used to configure some internal parameters of the given
 * @rule.
 */
static int seg6_local_end_ad_fib_rule_config(int action, struct fib_rule *rule)
{
	/* We don't want to resolve the source address so we mask out the flag */
	rule->flags &= ~FIB_RULE_FIND_SADDR;

	return 0;
}

static int seg6_local_end_ad_fib_rule_save_context(int action,
		struct fib_rule *rule, struct flowi *fl, void **context)
{
	struct seg6_local_end_ad_fib_rule_context *ctx;
	struct flowi6 *flp6 = &fl->u.ip6;

	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return -ENOMEM;

	memcpy(&ctx->saddr, &flp6->saddr, sizeof(struct in6_addr));
	memcpy(&ctx->daddr, &flp6->daddr, sizeof(struct in6_addr));

	*context = (void *) ctx;

	//pr_debug("seg6_local_end_ad_fib_rule_save_context: context saved.\n");

	return 1;
}

static int seg6_local_end_ad_fib_rule_restore_context(int action,
		struct fib_rule *rule, struct flowi *fl, void **context)
{
	struct seg6_local_end_ad_fib_rule_context *ctx;
	struct flowi6 *flp6 = &fl->u.ip6;

	if (!(*context))
		return 0;

	ctx = (struct seg6_local_end_ad_fib_rule_context *) (*context);

	/*
	 * We restore flp6 saddr and daddr because of they could have been
	 * changed during the seg6_local_fib_rule*() procesesing.
	 */
	memcpy(&flp6->saddr, &ctx->saddr, sizeof(struct in6_addr));
	memcpy(&flp6->daddr, &ctx->daddr, sizeof(struct in6_addr));

	kfree(ctx);
	*context = NULL;

	//pr_debug("seg6_local_end_ad_fib_rule_restore_context: context restored.\n");

	return 0;
}

static int seg6_local_end_ad_fib_rule_action(int action, struct fib_rule *rule,
					     struct flowi *fl, int flags,
					     void *arg)
{
	struct flowi6 *fl6 = &fl->u.ip6;

	/*
	 * We set @fl6->saddr to :: because of we don't want perform the lookup
	 * operation on the basis of a specific src address.
	 */
	ipv6_addr_set(&fl6->saddr, 0, 0, 0, 0);
	memcpy(&fl6->daddr, &fl6->fl6_seg6_local_sid, sizeof(struct in6_addr));

	return 0;
}

static int seg6_local_end_ad_fib_rule_match(
		int action, struct fib_rule *rule, struct flowi *fl, int flags)
{
	struct net *net = rule->fr_net;
	struct flowi6 *fl6 = &fl->u.ip6;
	struct seg6_local_spinfo_key *spinfo_key;
	struct in6_addr *sid;
	int iif, rc;

	iif = fl6->flowi6_iif;
	if (!iif)
		return 0;

	rcu_read_lock();

	rc = 0;
	spinfo_key = seg6_local_spinfo_key_lookup(net, iif);
	if (!spinfo_key)
		goto out;

	sid = &spinfo_key->sid.addr;

	/*
	 * We retrieve the info related to the key, so we can fill the
	 * @fl6_seg6_local_sid and @fl6_seg6_local_table_id. We need to change
	 * the @fl even though the  match() operation should be a idempotent
	 * operation. This is due to lack of output params in
	 * fib6_rules_ops->match() for passing extra data to the caller.
	 *
	 * NOTICE: fib_rule_match() in fib_rules.c takes an extra param called
	 * args which is used to pass data to the caller, if needed.
	 * We don't want to add seg6_local_fib_rule_match() within
	 * the fib_rules.c because of it should be leave as much general
	 * as possibile. Because of seg6 is only available with ipv6,
	 * adding the above callback directly inside the fib_rule_match()
	 * would be an error. As result, seg6_local_fib_rule_match() is placed
	 * inside fib6_rule_match that does not offer any ancillary output data.
	 */
	memcpy(&fl6->fl6_seg6_local_sid, sid, sizeof(*sid));
	fl6->fl6_seg6_local_table_id = spinfo_key->table_id;

	rc = 1;

	//pr_debug("seg6_local_end_ad_fib_rule_match: match found.\n");

out:
	rcu_read_unlock();

	return rc;
}

/* @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ */


static struct seg6_action_desc seg6_action_table[] = {
	{
		.action		= SEG6_LOCAL_ACTION_END,
		.attrs		= 0,
		.input		= input_action_end,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_X,
		.attrs		= (1 << SEG6_LOCAL_NH6),
		.input		= input_action_end_x,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_T,
		.attrs		= (1 << SEG6_LOCAL_TABLE),
		.input		= input_action_end_t,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX2,
		.attrs		= (1 << SEG6_LOCAL_OIF),
		.input		= input_action_end_dx2,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX6,
		.attrs		= (1 << SEG6_LOCAL_NH6),
		.input		= input_action_end_dx6,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX4,
		.attrs		= (1 << SEG6_LOCAL_NH4),
		.input		= input_action_end_dx4,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DT6,
		.attrs		= (1 << SEG6_LOCAL_TABLE),
		.input		= input_action_end_dt6,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_B6,
		.attrs		= (1 << SEG6_LOCAL_SRH),
		.input		= input_action_end_b6,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_B6_ENCAP,
		.attrs		= (1 << SEG6_LOCAL_SRH),
		.input		= input_action_end_b6_encap,
		.static_headroom	= sizeof(struct ipv6hdr),
	},
	{
		/*
		 * $Andrea
		 * End.AD support
		 */
		.action		  = SEG6_LOCAL_ACTION_END_AD,
		.attrs		  = SEG6_LOCAL_END_AD_ATTRS,
		.varattrs_allowed = SEG6_LOCAL_END_AD_NH_PROTO_VARATTRS,
		.input		  = end_ad,
		.slwt_ops = {
			.build_state	= seg6_local_end_ad_build_state,
			.destroy_state	= seg6_local_end_ad_destroy_state,
		},
		.fib_ops = {
			.rule_config	= seg6_local_end_ad_fib_rule_config,
			.rule_save_ctx  = seg6_local_end_ad_fib_rule_save_context,
			.rule_restore_ctx = seg6_local_end_ad_fib_rule_restore_context,
			.rule_match	= seg6_local_end_ad_fib_rule_match,
			.rule_action	= seg6_local_end_ad_fib_rule_action,
		},
	},
};

static struct seg6_action_desc *__get_action_desc(int action)
{
	struct seg6_action_desc *desc;
	int i, count;

	count = sizeof(seg6_action_table) / sizeof(struct seg6_action_desc);
	for (i = 0; i < count; i++) {
		desc = &seg6_action_table[i];
		if (desc->action == action)
			return desc;
	}

	return NULL;
}

static int seg6_local_input(struct sk_buff *skb)
{
	struct dst_entry *orig_dst = skb_dst(skb);
	struct seg6_action_desc *desc;
	struct seg6_local_lwt *slwt;

	if (skb->protocol != htons(ETH_P_IPV6)) {
		kfree_skb(skb);
		return -EINVAL;
	}

	slwt = seg6_local_lwtunnel(orig_dst->lwtstate);
	desc = slwt->desc;

	return desc->input(skb, slwt);
}

static const struct nla_policy seg6_local_policy[SEG6_LOCAL_MAX + 1] = {
	[SEG6_LOCAL_ACTION]	= { .type = NLA_U32 },
	[SEG6_LOCAL_SRH]	= { .type = NLA_BINARY },
	[SEG6_LOCAL_TABLE]	= { .type = NLA_U32 },
	[SEG6_LOCAL_NH4]	= { .type = NLA_BINARY,
				    .len = sizeof(struct in_addr) },
	[SEG6_LOCAL_NH6]	= { .type = NLA_BINARY,
				    .len = sizeof(struct in6_addr) },
	[SEG6_LOCAL_IIF]	= { .type = NLA_U32 },
	[SEG6_LOCAL_OIF]	= { .type = NLA_U32 },
	/* $Andrea */
	[SEG6_LOCAL_NHETH]      = { .type = NLA_BINARY, .len = ETH_ALEN },
	/* $Andrea */
	[SEG6_LOCAL_TIMEOUT]	= { .type = NLA_U32 },
};

static int parse_nla_srh(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	int len;

	srh = nla_data(attrs[SEG6_LOCAL_SRH]);
	len = nla_len(attrs[SEG6_LOCAL_SRH]);

	/* SRH must contain at least one segment */
	if (len < sizeof(*srh) + sizeof(struct in6_addr))
		return -EINVAL;

	if (!seg6_validate_srh(srh, len))
		return -EINVAL;

	/* FIXME: maybe a bug ... */
	slwt->srh = kmalloc(len, GFP_KERNEL);
	if (!slwt->srh)
		return -ENOMEM;

	memcpy(slwt->srh, srh, len);

	slwt->headroom += len;

	return 0;
}

static int put_nla_srh(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	struct nlattr *nla;
	int len;

	srh = slwt->srh;
	len = (srh->hdrlen + 1) << 3;

	nla = nla_reserve(skb, SEG6_LOCAL_SRH, len);
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), srh, len);

	return 0;
}

static int cmp_nla_srh(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	int len = (a->srh->hdrlen + 1) << 3;

	if (len != ((b->srh->hdrlen + 1) << 3))
		return 1;

	return memcmp(a->srh, b->srh, len);
}

static int parse_nla_table(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->table = nla_get_u32(attrs[SEG6_LOCAL_TABLE]);

	return 0;
}

static int put_nla_table(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	if (nla_put_u32(skb, SEG6_LOCAL_TABLE, slwt->table))
		return -EMSGSIZE;

	return 0;
}

static int cmp_nla_table(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->table != b->table)
		return 1;

	return 0;
}

static int parse_nla_nh4(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	memcpy(&slwt->nh4, nla_data(attrs[SEG6_LOCAL_NH4]),
	       sizeof(struct in_addr));

	return 0;
}

static int put_nla_nh4(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(skb, SEG6_LOCAL_NH4, sizeof(struct in_addr));
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), &slwt->nh4, sizeof(struct in_addr));

	return 0;
}

static int cmp_nla_nh4(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	return memcmp(&a->nh4, &b->nh4, sizeof(struct in_addr));
}

static int parse_nla_nh6(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	memcpy(&slwt->nh6, nla_data(attrs[SEG6_LOCAL_NH6]),
	       sizeof(struct in6_addr));

	return 0;
}

static int put_nla_nh6(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(skb, SEG6_LOCAL_NH6, sizeof(struct in6_addr));
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), &slwt->nh6, sizeof(struct in6_addr));

	return 0;
}

static int cmp_nla_nh6(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	return memcmp(&a->nh6, &b->nh6, sizeof(struct in6_addr));
}

static int parse_nla_iif(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->iif = nla_get_u32(attrs[SEG6_LOCAL_IIF]);

	return 0;
}

static int put_nla_iif(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	if (nla_put_u32(skb, SEG6_LOCAL_IIF, slwt->iif))
		return -EMSGSIZE;

	return 0;
}

static int cmp_nla_iif(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->iif != b->iif)
		return 1;

	return 0;
}

static int parse_nla_oif(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->oif = nla_get_u32(attrs[SEG6_LOCAL_OIF]);

	return 0;
}

static int put_nla_oif(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	if (nla_put_u32(skb, SEG6_LOCAL_OIF, slwt->oif))
		return -EMSGSIZE;

	return 0;
}

static int cmp_nla_oif(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->oif != b->oif)
		return 1;

	return 0;
}

/*
 * $Andrea
 */
static int parse_nla_nheth(struct nlattr **attrs,
		struct seg6_local_lwt *slwt)
{
	unsigned char *ethaddr;

	ethaddr = nla_data(attrs[SEG6_LOCAL_NHETH]);
	memcpy(slwt->nheth, ethaddr, ETH_ALEN);

	return 0;
}

/*
 * $Andrea
 */
static int put_nla_nheth(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(skb, SEG6_LOCAL_NHETH, ETH_ALEN);
	if (!nla)
		return -EMSGSIZE;

	memcpy(nla_data(nla), slwt->nheth, ETH_ALEN);

	return 0;
}

/*
 * $Andrea
 */
static int cmp_nla_nheth(struct seg6_local_lwt *a,
		struct seg6_local_lwt *b)
{
	return memcmp(a->nheth, b->nheth, ETH_ALEN);
}

/*
 * $Andrea
 */
static int parse_nla_timeout(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->timeout = nla_get_u32(attrs[SEG6_LOCAL_TIMEOUT]);

	return 0;
}

/*
 * $Andrea
 */
static int put_nla_timeout(struct sk_buff *skb, struct seg6_local_lwt *slwt)
{
	if (nla_put_u32(skb, SEG6_LOCAL_TIMEOUT, slwt->timeout))
		return -EMSGSIZE;

	return 0;
}

/*
 * $Andrea
 */
static int cmp_nla_timeout(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->timeout != b->timeout)
		return 1;

	return 0;
}



struct seg6_action_param {
	int (*parse)(struct nlattr **attrs, struct seg6_local_lwt *slwt);
	int (*put)(struct sk_buff *skb, struct seg6_local_lwt *slwt);
	int (*cmp)(struct seg6_local_lwt *a, struct seg6_local_lwt *b);
};

/*
 * XXX: If a structure or an array do not change after its definition then it
 * should  be better to declare it as read only or 'const'. This avoid accidental
 * overwriting of its content.
 */
static struct seg6_action_param seg6_action_params[SEG6_LOCAL_MAX + 1] = {
	[SEG6_LOCAL_SRH]	= { .parse = parse_nla_srh,
				    .put = put_nla_srh,
				    .cmp = cmp_nla_srh },

	[SEG6_LOCAL_TABLE]	= { .parse = parse_nla_table,
				    .put = put_nla_table,
				    .cmp = cmp_nla_table },

	[SEG6_LOCAL_NH4]	= { .parse = parse_nla_nh4,
				    .put = put_nla_nh4,
				    .cmp = cmp_nla_nh4 },

	[SEG6_LOCAL_NH6]	= { .parse = parse_nla_nh6,
				    .put = put_nla_nh6,
				    .cmp = cmp_nla_nh6 },

	[SEG6_LOCAL_IIF]	= { .parse = parse_nla_iif,
				    .put = put_nla_iif,
				    .cmp = cmp_nla_iif },

	[SEG6_LOCAL_OIF]	= { .parse = parse_nla_oif,
				    .put = put_nla_oif,
				    .cmp = cmp_nla_oif },
	/* $Andrea */
	[SEG6_LOCAL_NHETH]	= { .parse = parse_nla_nheth,
				    .put = put_nla_nheth,
				    .cmp = cmp_nla_nheth },
	/* $Andrea */
	[SEG6_LOCAL_TIMEOUT]	= { .parse = parse_nla_timeout,
				    .put = put_nla_timeout,
				    .cmp = cmp_nla_timeout },

};

/*
 * $Andrea
 *
 * This function allows to parse optional/var attributes that may have been
 * provided during the definition of @seg6_action_params.
 * Optional/var attributes differ from the mandatory ones because of they can be
 * or they cannot be present at all; if an attribute is declared but is not
 * given then it will be simply discarded without generating any error.
 *
 * This functionality give us the ability to use different parameters
 * configuration for a given srv6 behaviour that cannot be completely defined
 * at @seg6_action_params creation.
 * An example would be the End.AD behaviour where we can accept more than one
 * nexthop protocol but we don't know in advance what it will be; so we allow
 * the user to select one of nexthop available protocols and we take care of
 * validate its choosing.
 */
static int parse_nla_var_attrs(struct nlattr **attrs,
		struct seg6_local_lwt *slwt)
{
	struct seg6_action_param *param;
	struct seg6_action_desc *desc;
	unsigned long varattrs_allowed, varattrs;
	int i, err;

	varattrs = 0;
	desc = slwt->desc;
	varattrs_allowed = desc->varattrs_allowed;

	if (!varattrs_allowed)
		goto out;
	/*
	 * We call the parse function for each var attribute.
	 *
	 * NOTICE: Mandatory attributes have already been parsed.
	 */
	for(i = 0; i < SEG6_LOCAL_MAX + 1; ++i) {
		if (varattrs_allowed & (1 << i)) {
			if (!attrs[i])
				continue;

			/* 'i' parameter is allowed and is available */
			varattrs |= (1 << i);
			param = &seg6_action_params[i];

			err = param->parse(attrs, slwt);
			if (err < 0)
				return err;
		}
	}

out:
	/*
	 * We store the varattrs mask so that we can always know which are
	 * the optional parameters and which ones are not.
	 */
	slwt->varattrs = varattrs;

	return 0;
}

static int parse_nla_action(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct seg6_action_param *param;
	struct seg6_action_desc *desc;
	int i, err;

	desc = __get_action_desc(slwt->action);
	if (!desc)
		return -EINVAL;

	if (!desc->input)
		return -EOPNOTSUPP;

	slwt->desc = desc;
	slwt->headroom += desc->static_headroom;

	for (i = 0; i < SEG6_LOCAL_MAX + 1; i++) {
		if (desc->attrs & (1 << i)) {
			if (!attrs[i])
				return -EINVAL;

			param = &seg6_action_params[i];

			err = param->parse(attrs, slwt);
			if (err < 0)
				return err;
		}
	}

	/* If @desc allows var attributes then we parse all of them. */
	err = parse_nla_var_attrs(attrs, slwt);
	if (err)
		return err;

	return 0;
}

/**
 * Returns the pointer to the seg6_local_fib_ops structure associated with
 * the given @action.
 */
static inline struct seg6_local_fib_ops *get_seg6_local_fib_ops(int action)
{
	struct seg6_action_desc *desc;

	if (!action)
		return NULL;

	desc = __get_action_desc(action);
	if (unlikely(!desc))
		return NULL;

	return &desc->fib_ops;
}

/**
 * This function checks for the match and action callbacks. If those callback
 * are available then the behaviour is considered supported and the function
 * returns 0; otherwise it returns an error < 0.
 */
static inline int seg6_local_fib_rule_behaviour_check_support(int action)
{
	struct seg6_local_fib_ops *fib_ops;

	fib_ops = get_seg6_local_fib_ops(action);
	if (unlikely(!fib_ops))
		return -EINVAL;

	if (!fib_ops->rule_match || !fib_ops->rule_action)
		return -EOPNOTSUPP;

	return 0;
}

/**
 * This function executes the 'seg6_local_fib_ops->rule_config' callback for the
 * given @action, if any.
 */
int seg6_local_fib_rule_config(int action, struct fib_rule* rule)
{
	struct seg6_local_fib_ops *fib_ops;
	int err;

	/* The current behaviour is not supported */
	err = seg6_local_fib_rule_behaviour_check_support(action);
	if (err)
		return err;

	fib_ops = get_seg6_local_fib_ops(action);
	if (unlikely(!fib_ops))
		return -EINVAL;

	if (!fib_ops->rule_config)
		return 0;

	return fib_ops->rule_config(action, rule);
}

/**
 * see seg6_local_fib_rule_config() for details.
 */
int seg6_local_fib_rule_match(int action, struct fib_rule *rule,
		struct flowi *fl, int flags)
{
	struct seg6_local_fib_ops *fib_ops;

	fib_ops = get_seg6_local_fib_ops(action);
	if (unlikely(!fib_ops))
		return 0;

	if (unlikely(!fib_ops->rule_match))
		return -EOPNOTSUPP;

	return fib_ops->rule_match(action, rule, fl, flags);
}

/**
 * see seg6_local_fib_rule_config() for details.
 */
int seg6_local_fib_rule_action(int action, struct fib_rule *rule,
		struct flowi *fl, int flags, void *arg)
{
	struct seg6_local_fib_ops *fib_ops;

	fib_ops = get_seg6_local_fib_ops(action);
	if (unlikely(!fib_ops))
		return -EINVAL;

	if (unlikely(!fib_ops->rule_action))
		return -EOPNOTSUPP;

	return fib_ops->rule_action(action, rule, fl, flags, arg);
}

/**
 * see seg6_local_fib_rule_config() for details.
 */
int seg6_local_fib_rule_save_context(int action, struct fib_rule *rule,
		struct flowi *fl, void **context)
{
	struct seg6_local_fib_ops *fib_ops;

	fib_ops = get_seg6_local_fib_ops(action);
	if (unlikely(!fib_ops))
		return -EINVAL;

	if (!fib_ops->rule_save_ctx)
		return 0;

	return fib_ops->rule_save_ctx(action, rule, fl, context);
}

/**
 * see seg6_local_fib_rule_config() for details.
 */
int seg6_local_fib_rule_restore_context(int action, struct fib_rule *rule,
		struct flowi *fl, void **context)
{
	struct seg6_local_fib_ops *fib_ops;

	fib_ops = get_seg6_local_fib_ops(action);
	if (unlikely(!fib_ops))
		return -EINVAL;

	if (!fib_ops->rule_restore_ctx)
		return 0;

	return fib_ops->rule_restore_ctx(action, rule, fl, context);
}

/*
 * $Andrea
 * Called on seg6_local_lwt's tunnel creation.
 */
static int seg6_local_build_state(struct nlattr *nla, unsigned int family,
				  const void *cfg, struct lwtunnel_state **ts,
				  struct netlink_ext_ack *extack)
{
	struct nlattr *tb[SEG6_LOCAL_MAX + 1];
	struct lwtunnel_state *newts;
	struct seg6_local_lwt *slwt;
	int err;

	if (family != AF_INET6)
		return -EINVAL;

	err = nla_parse_nested(tb, SEG6_LOCAL_MAX, nla, seg6_local_policy,
			       extack);

	if (err < 0)
		return err;

	if (!tb[SEG6_LOCAL_ACTION])
		return -EINVAL;

	newts = lwtunnel_state_alloc(sizeof(*slwt));
	if (!newts)
		return -ENOMEM;

	slwt = seg6_local_lwtunnel(newts);
	slwt->action = nla_get_u32(tb[SEG6_LOCAL_ACTION]);

	err = parse_nla_action(tb, slwt);
	if (err < 0)
		goto out_free;

	/* Parameters are ok, so we can call the custom function, if any. */
	err = seg6_local_lwtunnel_build_state(slwt, cfg);
	if (err < 0)
		goto out_free;

	newts->type = LWTUNNEL_ENCAP_SEG6_LOCAL;
	newts->flags = LWTUNNEL_STATE_INPUT_REDIRECT;
	newts->headroom = slwt->headroom;

	*ts = newts;

	return 0;

out_free:
	kfree(slwt->srh);
	kfree(newts);

	return err;
}

static void seg6_local_destroy_state(struct lwtunnel_state *lwt)
{
	struct seg6_local_lwt *slwt = seg6_local_lwtunnel(lwt);
	seg6_local_lwtunnel_destroy_state(slwt);
	kfree(slwt->srh);
}

static int seg6_local_fill_encap(struct sk_buff *skb,
				 struct lwtunnel_state *lwt)
{
	struct seg6_local_lwt *slwt = seg6_local_lwtunnel(lwt);
	struct seg6_action_param *param;
	unsigned long attrs;
	int i, err;

	if (nla_put_u32(skb, SEG6_LOCAL_ACTION, slwt->action))
		return -EMSGSIZE;

	/**
	 * The set of attributes is made of two part:
	 * 1) Mandatory attrs (the default attributes)
	 * 2) Variable number of optional attributes
	 */
	attrs = slwt->desc->attrs | slwt->varattrs;

	for (i = 0; i < SEG6_LOCAL_MAX + 1; i++) {
		if (attrs & (1 << i)) {
			param = &seg6_action_params[i];
			err = param->put(skb, slwt);
			if (err < 0)
				return err;
		}
	}

	return 0;
}

static int seg6_local_get_encap_size(struct lwtunnel_state *lwt)
{
	struct seg6_local_lwt *slwt = seg6_local_lwtunnel(lwt);
	unsigned long attrs;
	int nlsize;

	nlsize = nla_total_size(4); /* action */

	/* $Andrea, see above for description */
	attrs = slwt->desc->attrs | slwt->varattrs;

	if (attrs & (1 << SEG6_LOCAL_SRH))
		nlsize += nla_total_size((slwt->srh->hdrlen + 1) << 3);

	if (attrs & (1 << SEG6_LOCAL_TABLE))
		nlsize += nla_total_size(4);

	if (attrs & (1 << SEG6_LOCAL_NH4))
		nlsize += nla_total_size(4);

	if (attrs & (1 << SEG6_LOCAL_NH6))
		nlsize += nla_total_size(16);

	if (attrs & (1 << SEG6_LOCAL_IIF))
		nlsize += nla_total_size(4);

	if (attrs & (1 << SEG6_LOCAL_OIF))
		nlsize += nla_total_size(4);

	/* $Andrea */
	if (attrs & (1 << SEG6_LOCAL_NHETH))
		nlsize += nla_total_size(ETH_ALEN);

	/* $Andrea */
	if (attrs & (1 << SEG6_LOCAL_TIMEOUT))
		nlsize += nla_total_size(4);

	return nlsize;
}

static int seg6_local_cmp_encap(struct lwtunnel_state *a,
				struct lwtunnel_state *b)
{
	struct seg6_local_lwt *slwt_a, *slwt_b;
	struct seg6_action_param *param;
	int i;
	unsigned long attrs_a, attrs_b;

	slwt_a = seg6_local_lwtunnel(a);
	slwt_b = seg6_local_lwtunnel(b);

	if (slwt_a->action != slwt_b->action)
		return 1;

	/* $Andrea */
	attrs_a = slwt_a->desc->attrs | slwt_a->varattrs;
	attrs_b = slwt_b->desc->attrs | slwt_b->varattrs;

	if (attrs_a != attrs_b)
		return 1;

	for (i = 0; i < SEG6_LOCAL_MAX + 1; i++) {
		if (attrs_a & (1 << i)) {
			param = &seg6_action_params[i];
			if (param->cmp(slwt_a, slwt_b))
				return 1;
		}
	}

	return 0;
}

static const struct lwtunnel_encap_ops seg6_local_ops = {
	.build_state	= seg6_local_build_state,
	.destroy_state	= seg6_local_destroy_state,
	.input		= seg6_local_input,
	.fill_encap	= seg6_local_fill_encap,
	.get_encap_size	= seg6_local_get_encap_size,
	.cmp_encap	= seg6_local_cmp_encap,
	.owner		= THIS_MODULE,
};

int __init seg6_local_init(void)
{
	return lwtunnel_encap_add_ops(&seg6_local_ops,
				LWTUNNEL_ENCAP_SEG6_LOCAL);
}

void seg6_local_exit(void)
{
	lwtunnel_encap_del_ops(&seg6_local_ops, LWTUNNEL_ENCAP_SEG6_LOCAL);
}

/*
 * $Andrea
 * Called on namespace initialization.
 */
int __net_init seg6_local_net_init(struct net *net)
{
	struct seg6_local_pernet_data *seg6_local_data;
	struct seg6_local_spinfo *spinfo;
	int err;

	seg6_local_data = seg6_local_pernet(net);
	spinfo = &(seg6_local_data->spinfo);

	/* Standard configuration for ht_key (copy) */
	spinfo->spinfo_ht_params = spinfo_ht_default_params;
	err = rhashtable_init(&spinfo->spinfo_ht_key,
			      &spinfo->spinfo_ht_params);
	if (err)
		return err;

	return 0;
}

/*
 * $Andrea
 * Called on namespace destruction.
 */
void __net_exit seg6_local_net_exit(struct net *net)
{
	struct seg6_local_pernet_data *seg6_local_data;
	struct seg6_local_spinfo *spinfo;

	seg6_local_data = seg6_local_pernet(net);
	spinfo = &(seg6_local_data->spinfo);

	/**
	 * We destroy any key in the HT. We free memory only when nobody
	 * is referencing data anymore. This is possibile tanks to RCU:
	 * spinfo_key and spinfo_data are always accessed within an RCU
	 * critical section.
	 */
	rhashtable_free_and_destroy(&spinfo->spinfo_ht_key,
				    seg6_local_spinfo_key_free_hi, NULL);
}
