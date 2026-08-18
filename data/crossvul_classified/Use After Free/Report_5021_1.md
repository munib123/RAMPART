# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5021_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5021_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 188-228 of the vulnerable file.

	_DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field +256)
#define ICMP6MSGIN_INC_STATS_BH(net, idev, field)	\
	_DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field)

struct ip6_ra_chain {
	struct ip6_ra_chain	*next;
	struct sock		*sk;
	int			sel;
	void			(*destructor)(struct sock *);
};

extern struct ip6_ra_chain	*ip6_ra_chain;
extern rwlock_t ip6_ra_lock;

/*
   This structure is prepared by protocol, when parsing
   ancillary data and passed to IPv6.
 */

struct ipv6_txoptions {
	/* Length of this structure */
	int			tot_len;

	/* length of extension headers   */

	__u16			opt_flen;	/* after fragment hdr */
	__u16			opt_nflen;	/* before fragment hdr */

	struct ipv6_opt_hdr	*hopopt;
	struct ipv6_opt_hdr	*dst0opt;
	struct ipv6_rt_hdr	*srcrt;	/* Routing Header */
	struct ipv6_opt_hdr	*dst1opt;

	/* Option buffer, as read by IPV6_PKTOPTIONS, starts here. */
};

struct ip6_flowlabel {
	struct ip6_flowlabel __rcu *next;
	__be32			label;
	atomic_t		users;
	struct in6_addr		dst;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -205,6 +205,7 @@
  */
 
 struct ipv6_txoptions {
+	atomic_t		refcnt;
 	/* Length of this structure */
 	int			tot_len;
 
@@ -217,7 +218,7 @@
 	struct ipv6_opt_hdr	*dst0opt;
 	struct ipv6_rt_hdr	*srcrt;	/* Routing Header */
 	struct ipv6_opt_hdr	*dst1opt;
-
+	struct rcu_head		rcu;
 	/* Option buffer, as read by IPV6_PKTOPTIONS, starts here. */
 };
 
@@ -252,6 +253,24 @@
 	struct rcu_head			rcu;
 };
 
+static inline struct ipv6_txoptions *txopt_get(const struct ipv6_pinfo *np)
+{
+	struct ipv6_txoptions *opt;
+
+	rcu_read_lock();
+	opt = rcu_dereference(np->opt);
+	if (opt && !atomic_inc_not_zero(&opt->refcnt))
+		opt = NULL;
+	rcu_read_unlock();
+	return opt;
+}
+
+static inline void txopt_put(struct ipv6_txoptions *opt)
+{
+	if (opt && atomic_dec_and_test(&opt->refcnt))
+		kfree_rcu(opt, rcu);
+}
+
 struct ip6_flowlabel *fl6_sock_lookup(struct sock *sk, __be32 label);
 struct ipv6_txoptions *fl6_merge_options(struct ipv6_txoptions *opt_space,
 					 struct ip6_flowlabel *fl,
```
