# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3726_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3726_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 31-71 of the vulnerable file.

#include "ccid.h"
#include "dccp.h"
#include "feat.h"

/*
 * The per-net dccp.v4_ctl_sk socket is used for responding to
 * the Out-of-the-blue (OOTB) packets. A control sock will be created
 * for this socket at the initialization time.
 */

int dccp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	const struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);
	__be16 orig_sport, orig_dport;
	__be32 daddr, nexthop;
	struct flowi4 fl4;
	struct rtable *rt;
	int err;

	dp->dccps_role = DCCP_ROLE_CLIENT;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	nexthop = daddr = usin->sin_addr.s_addr;
	if (inet->opt != NULL && inet->opt->srr) {
		if (daddr == 0)
			return -EINVAL;
		nexthop = inet->opt->faddr;
	}

	orig_sport = inet->inet_sport;
	orig_dport = usin->sin_port;
	rt = ip_route_connect(&fl4, nexthop, inet->inet_saddr,
			      RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			      IPPROTO_DCCP,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,7 @@
 	struct flowi4 fl4;
 	struct rtable *rt;
 	int err;
+	struct ip_options_rcu *inet_opt;
 
 	dp->dccps_role = DCCP_ROLE_CLIENT;
 
@@ -58,10 +59,13 @@
 		return -EAFNOSUPPORT;
 
 	nexthop = daddr = usin->sin_addr.s_addr;
-	if (inet->opt != NULL && inet->opt->srr) {
+
+	inet_opt = rcu_dereference_protected(inet->inet_opt,
+					     sock_owned_by_user(sk));
+	if (inet_opt != NULL && inet_opt->opt.srr) {
 		if (daddr == 0)
 			return -EINVAL;
-		nexthop = inet->opt->faddr;
+		nexthop = inet_opt->opt.faddr;
 	}
 
 	orig_sport = inet->inet_sport;
@@ -78,7 +82,7 @@
 		return -ENETUNREACH;
 	}
 
-	if (inet->opt == NULL || !inet->opt->srr)
+	if (inet_opt == NULL || !inet_opt->opt.srr)
 		daddr = rt->rt_dst;
 
 	if (inet->inet_saddr == 0)
@@ -89,8 +93,8 @@
 	inet->inet_daddr = daddr;
 
 	inet_csk(sk)->icsk_ext_hdr_len = 0;
-	if (inet->opt != NULL)
-		inet_csk(sk)->icsk_ext_hdr_len = inet->opt->optlen;
+	if (inet_opt)
+		inet_csk(sk)->icsk_ext_hdr_len = inet_opt->opt.optlen;
 	/*
 	 * Socket identity is still unknown (sport may be zero).
 	 * However we set state to DCCP_REQUESTING and not releasing socket
@@ -405,7 +409,7 @@
 	newinet->inet_daddr	= ireq->rmt_addr;
 	newinet->inet_rcv_saddr = ireq->loc_addr;
 	newinet->inet_saddr	= ireq->loc_addr;
-	newinet->opt	   = ireq->opt;
+	newinet->inet_opt	= ireq->opt;
 	ireq->opt	   = NULL;
 	newinet->mc_index  = inet_iif(skb);
 	newinet->mc_ttl	   = ip_hdr(skb)->ttl;
```
