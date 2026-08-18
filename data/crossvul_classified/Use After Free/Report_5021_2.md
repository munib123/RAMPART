# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5021_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5021_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 185-225 of the vulnerable file.

{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff *skb;
	struct in6_addr *final_p, final;
	struct flowi6 fl6;
	int err = -1;
	struct dst_entry *dst;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_DCCP;
	fl6.daddr = ireq->ir_v6_rmt_addr;
	fl6.saddr = ireq->ir_v6_loc_addr;
	fl6.flowlabel = 0;
	fl6.flowi6_oif = ireq->ir_iif;
	fl6.fl6_dport = ireq->ir_rmt_port;
	fl6.fl6_sport = htons(ireq->ir_num);
	security_req_classify_flow(req, flowi6_to_flowi(&fl6));


	final_p = fl6_update_dst(&fl6, np->opt, &final);

	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		dst = NULL;
		goto done;
	}

	skb = dccp_make_response(sk, dst, req);
	if (skb != NULL) {
		struct dccp_hdr *dh = dccp_hdr(skb);

		dh->dccph_checksum = dccp_v6_csum_finish(skb,
							 &ireq->ir_v6_loc_addr,
							 &ireq->ir_v6_rmt_addr);
		fl6.daddr = ireq->ir_v6_rmt_addr;
		err = ip6_xmit(sk, skb, &fl6, np->opt, np->tclass);
		err = net_xmit_eval(err);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,7 +202,9 @@
 	security_req_classify_flow(req, flowi6_to_flowi(&fl6));
 
 
-	final_p = fl6_update_dst(&fl6, np->opt, &final);
+	rcu_read_lock();
+	final_p = fl6_update_dst(&fl6, rcu_dereference(np->opt), &final);
+	rcu_read_unlock();
 
 	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
 	if (IS_ERR(dst)) {
@@ -219,7 +221,10 @@
 							 &ireq->ir_v6_loc_addr,
 							 &ireq->ir_v6_rmt_addr);
 		fl6.daddr = ireq->ir_v6_rmt_addr;
-		err = ip6_xmit(sk, skb, &fl6, np->opt, np->tclass);
+		rcu_read_lock();
+		err = ip6_xmit(sk, skb, &fl6, rcu_dereference(np->opt),
+			       np->tclass);
+		rcu_read_unlock();
 		err = net_xmit_eval(err);
 	}
 
@@ -387,6 +392,7 @@
 	struct inet_request_sock *ireq = inet_rsk(req);
 	struct ipv6_pinfo *newnp;
 	const struct ipv6_pinfo *np = inet6_sk(sk);
+	struct ipv6_txoptions *opt;
 	struct inet_sock *newinet;
 	struct dccp6_sock *newdp6;
 	struct sock *newsk;
@@ -488,13 +494,15 @@
 	 * Yes, keeping reference count would be much more clever, but we make
 	 * one more one thing there: reattach optmem to newsk.
 	 */
-	if (np->opt != NULL)
-		newnp->opt = ipv6_dup_options(newsk, np->opt);
-
+	opt = rcu_dereference(np->opt);
+	if (opt) {
+		opt = ipv6_dup_options(newsk, opt);
+		RCU_INIT_POINTER(newnp->opt, opt);
+	}
 	inet_csk(newsk)->icsk_ext_hdr_len = 0;
-	if (newnp->opt != NULL)
-		inet_csk(newsk)->icsk_ext_hdr_len = (newnp->opt->opt_nflen +
-						     newnp->opt->opt_flen);
+	if (opt)
+		inet_csk(newsk)->icsk_ext_hdr_len = opt->opt_nflen +
+						    opt->opt_flen;
 
 	dccp_sync_mss(newsk, dst_mtu(dst));
 
@@ -757,6 +765,7 @@
 	struct ipv6_pinfo *np = inet6_sk(sk);
 	struct dccp_sock *dp = dccp_sk(sk);
 	struct in6_addr *saddr = NULL, *final_p, final;
+	struct ipv6_txoptions *opt;
 	struct flowi6 fl6;
 	struct dst_entry *dst;
 	int addr_type;
@@ -856,7 +865,8 @@
 	fl6.fl6_sport = inet->inet_sport;
 	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));
 
-	final_p = fl6_update_dst(&fl6, np->opt, &final);
+	opt = rcu_dereference_protected(np->opt, sock_owned_by_user(sk));
+	final_p = fl6_update_dst(&fl6, opt, &final);
 
 	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
 	if (IS_ERR(dst)) {
@@ -876,9 +886,8 @@
 	__ip6_dst_store(sk, dst, NULL, NULL);
 
 	icsk->icsk_ext_hdr_len = 0;
-	if (np->opt != NULL)
-		icsk->icsk_ext_hdr_len = (np->opt->opt_flen +
-					  np->opt->opt_nflen);
+	if (opt)
+		icsk->icsk_ext_hdr_len = opt->opt_flen + opt->opt_nflen;
 
 	inet->inet_dport = usin->sin6_port;
 
```
