# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3726_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3726_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 40-80 of the vulnerable file.

 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	__be32		faddr;
	unsigned char	optlen;
	unsigned char	srr;
	unsigned char	rr;
	unsigned char	ts;
	unsigned char	is_strictroute:1,
			srr_is_hit:1,
			is_changed:1,
			rr_needaddr:1,
			ts_needtime:1,
			ts_needaddr:1;
	unsigned char	router_alert;
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[0];
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct inet_request_sock {
	struct request_sock	req;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
#endif
	__be16			loc_port;
	__be32			loc_addr;
	__be32			rmt_addr;
	__be16			rmt_port;
	kmemcheck_bitfield_begin(flags);
	u16			snd_wscale : 4,
				rcv_wscale : 4,
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1,
				no_srccheck: 1;
	kmemcheck_bitfield_end(flags);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,7 +57,15 @@
 	unsigned char	__data[0];
 };
 
-#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)
+struct ip_options_rcu {
+	struct rcu_head rcu;
+	struct ip_options opt;
+};
+
+struct ip_options_data {
+	struct ip_options_rcu	opt;
+	char			data[40];
+};
 
 struct inet_request_sock {
 	struct request_sock	req;
@@ -78,7 +86,7 @@
 				acked	   : 1,
 				no_srccheck: 1;
 	kmemcheck_bitfield_end(flags);
-	struct ip_options	*opt;
+	struct ip_options_rcu	*opt;
 };
 
 static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
@@ -140,7 +148,7 @@
 	__be16			inet_sport;
 	__u16			inet_id;
 
-	struct ip_options	*opt;
+	struct ip_options_rcu __rcu	*inet_opt;
 	__u8			tos;
 	__u8			min_ttl;
 	__u8			mc_ttl;
```
