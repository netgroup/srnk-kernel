#ifndef _LINUX_SEG6_LOCAL_H
#define _LINUX_SEG6_LOCAL_H

#include <net/seg6.h>
#include <net/dst_cache.h>

#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/rhashtable.h>
#include <linux/spinlock.h>

#define SEG6_LOCAL_END_AD_ATTRS					\
		 ((1 << SEG6_LOCAL_OIF)			|	\
		  (1 << SEG6_LOCAL_TIMEOUT))

#define SEG6_LOCAL_END_AD_NH_PROTO_VARATTRS			\
	((1 << SEG6_LOCAL_NH6)				|	\
	 (1 << SEG6_LOCAL_NHETH))

struct seg6_local_spinfo {
	struct rhashtable spinfo_ht_key;
	struct rhashtable_params spinfo_ht_params;
};

struct seg6_local_spinfo_header {
	struct ipv6hdr *ipv6_hdr;
	struct ipv6_sr_hdr *ipv6_sr_hdr;
};

struct seg6_local_spinfo_data {
	struct rcu_head __rcu rcu;

	u64 aging_jiffies;
	struct seg6_local_spinfo_header hdr;
	/*
	 * Cache is used to avoid ipv6 lookup every time a packet comes from
	 * southbound and we need to find out its destination.
	 * Lookup operations are heavy, so it is better to reuse cached results
	 * if they are available.
	 */
	struct dst_cache cache;
};

/*
 * Key used to lookup and get spinfo's data.
 */
struct seg6_local_spinfo_key {
	struct rcu_head __rcu rcu;
	struct rhash_head node;
	unsigned long state;
	struct rt6key sid;
	spinlock_t lock;
	u32 table_id;
	u32 key;

	struct seg6_local_spinfo_data __rcu *data;
#define SEG6_LOCAL_SPINFO_KEY_VALID		(0)
#define SEG6_LOCAL_SPINFO_KEY_INVALID		(1)
};

struct seg6_local_pernet_data {
	struct seg6_local_spinfo spinfo;
};

/*
 * Moved here due to module access.
 */
struct seg6_local_lwt;

/*
 * This struct is used to wrap callbacks used for fib operations.
 */
struct seg6_local_fib_ops {
	/*
	 * Allows to perform fine tuning on the rule which is going to be
	 * created.
	 *
	 * This callback is optional.
	 */
	int (*rule_config)(int action, struct fib_rule *rule);

	/*
	 * Takes a snapshot of @rule, @flp and save it into @context.
	 * The function returns 0 if operation completes successfully but no
	 * data has been saved; returns > 0 if the operations completes
	 * successfully and data has been saved. Otherwise it returns an error <
	 * 0.
	 *
	 * This callback is optional.
	 */
	int (*rule_save_ctx)(int action, struct fib_rule *rule,
				struct flowi *flp, void **context);
	/*
	 * Restores the snapshot of @flp if it has been previously taken by the
	 * @rule_save_ctx callback. The snapshot is referenced by the @context
	 * parameter, if it is different from NULL.
	 *
	 * This callback is optional.
	 */
	int (*rule_restore_ctx)(int action, struct fib_rule *rule,
				struct flowi *flp, void **context);

	int (*rule_action)(int action, struct fib_rule *rule,
				struct flowi *fl, int flags, void *arg);
	int (*rule_match)(int action, struct fib_rule *rule,
				struct flowi *fl, int flags);
};

/*
 * This struct allows to customize lwt's creation and lwt's destruction.
 */
struct seg6_local_lwtunnel_ops {
	int (*build_state)(struct seg6_local_lwt *slwt, const void *cfg);
	int (*destroy_state)(struct seg6_local_lwt *slwt);
};

struct seg6_action_desc {
	unsigned long attrs;
	int action;

	/*
	 * $Andrea
	 * This field is used to specify other attrs wich can be defined as
	 * optional parameters. If one of this attribute in not present in the
	 * ntlink message then it will be discarded without returning any error
	 * (in case of attrs it returns -EINVAL error to userland).
	 */
	unsigned long varattrs_allowed;

	int (*input)(struct sk_buff *skb, struct seg6_local_lwt *slwt);
	int static_headroom;

	/*
	 * $Andrea
	 * This callback is called during lwt's building phase.
	 * It allows us to customize lwt, i.e: we can create some usefull
	 * data structures that will be used in the input function.
	 */
	struct seg6_local_lwtunnel_ops slwt_ops;
		
	/* $Andrea: extended IPv6 rule support */
	struct seg6_local_fib_ops fib_ops;
};

struct seg6_local_lwt {
	/* Those values are filled through ip -6 route add command */
	struct ipv6_sr_hdr *srh;
	int action;
	int table;
	/*
	 *  We only use one field at a time for each seg6_local_lwt.
	 */
	union {
		struct in_addr nh4;
		struct in6_addr nh6;

		/*
		 * $Andrea
		 * @nheth is the ethernet DA for packet forwarding from
		 * NORTH to SOUTH in End.AD.
		 */
		unsigned char nheth[ETH_ALEN];
	};

	/*
	 * $Andrea
	 * This field is used when a behaviour can accept more than a nexthop
	 * address protocol.
	 */
	int nh_proto;

	/*
	 * $Andrea
	 * Timeout/aging time for Proxy (End.AD)
	 */
	int timeout;

	int iif;
	int oif;

	int headroom;
	struct seg6_action_desc *desc;

	/*
	 * $Andrea
	 * Those are optional parameters which have been parsed; this field
	 * cannot be put in seg6_action_desc because of they reflect the result
	 * of the parsing operation which is proper for each lwt tunnel. In
	 * other words this is a private information for each tunnel.
	 */
	unsigned long varattrs;

	/*
	 * $Andrea
	 * @private data can be used to store usefull data
	 */
	void *private_data;
};

/* $Andrea */
extern int seg6_local_fib_rule_config(int action, struct fib_rule *rule);
extern int seg6_local_fib_rule_match(int action, struct fib_rule *rule,
		struct flowi *fl, int flags);
extern int seg6_local_fib_rule_action(int action, struct fib_rule *rule,
		struct flowi *fl, int flags, void *arg);
extern int seg6_local_fib_rule_save_context(int action, struct fib_rule *rule,
		struct flowi *fl, void **context);
extern int seg6_local_fib_rule_restore_context(int action,
		struct fib_rule *rule, struct flowi *fl, void **context);

extern struct seg6_local_pernet_data *seg6_local_pernet(struct net *net);
extern int  __net_init seg6_local_net_init(struct net *net);
extern void __net_exit seg6_local_net_exit(struct net *net);

#include <uapi/linux/seg6_local.h>

#endif
