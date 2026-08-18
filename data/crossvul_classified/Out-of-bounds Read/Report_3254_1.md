# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3254_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3254_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3776-3816 of the vulnerable file.

	struct sk_buff *clone;

	if (!sk || !atomic_inc_not_zero(&sk->sk_refcnt))
		return NULL;

	clone = skb_clone(skb, GFP_ATOMIC);
	if (!clone) {
		sock_put(sk);
		return NULL;
	}

	clone->sk = sk;
	clone->destructor = sock_efree;

	return clone;
}
EXPORT_SYMBOL(skb_clone_sk);

static void __skb_complete_tx_timestamp(struct sk_buff *skb,
					struct sock *sk,
					int tstype)
{
	struct sock_exterr_skb *serr;
	int err;

	serr = SKB_EXT_ERR(skb);
	memset(serr, 0, sizeof(*serr));
	serr->ee.ee_errno = ENOMSG;
	serr->ee.ee_origin = SO_EE_ORIGIN_TIMESTAMPING;
	serr->ee.ee_info = tstype;
	if (sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID) {
		serr->ee.ee_data = skb_shinfo(skb)->tskey;
		if (sk->sk_protocol == IPPROTO_TCP &&
		    sk->sk_type == SOCK_STREAM)
			serr->ee.ee_data -= sk->sk_tskey;
	}

	err = sock_queue_err_skb(sk, skb);

	if (err)
		kfree_skb(skb);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3793,16 +3793,20 @@
 
 static void __skb_complete_tx_timestamp(struct sk_buff *skb,
 					struct sock *sk,
-					int tstype)
+					int tstype,
+					bool opt_stats)
 {
 	struct sock_exterr_skb *serr;
 	int err;
+
+	BUILD_BUG_ON(sizeof(struct sock_exterr_skb) > sizeof(skb->cb));
 
 	serr = SKB_EXT_ERR(skb);
 	memset(serr, 0, sizeof(*serr));
 	serr->ee.ee_errno = ENOMSG;
 	serr->ee.ee_origin = SO_EE_ORIGIN_TIMESTAMPING;
 	serr->ee.ee_info = tstype;
+	serr->opt_stats = opt_stats;
 	if (sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID) {
 		serr->ee.ee_data = skb_shinfo(skb)->tskey;
 		if (sk->sk_protocol == IPPROTO_TCP &&
@@ -3843,7 +3847,7 @@
 	 */
 	if (likely(atomic_inc_not_zero(&sk->sk_refcnt))) {
 		*skb_hwtstamps(skb) = *hwtstamps;
-		__skb_complete_tx_timestamp(skb, sk, SCM_TSTAMP_SND);
+		__skb_complete_tx_timestamp(skb, sk, SCM_TSTAMP_SND, false);
 		sock_put(sk);
 	}
 }
@@ -3854,7 +3858,7 @@
 		     struct sock *sk, int tstype)
 {
 	struct sk_buff *skb;
-	bool tsonly;
+	bool tsonly, opt_stats = false;
 
 	if (!sk)
 		return;
@@ -3867,9 +3871,10 @@
 #ifdef CONFIG_INET
 		if ((sk->sk_tsflags & SOF_TIMESTAMPING_OPT_STATS) &&
 		    sk->sk_protocol == IPPROTO_TCP &&
-		    sk->sk_type == SOCK_STREAM)
+		    sk->sk_type == SOCK_STREAM) {
 			skb = tcp_get_timestamping_opt_stats(sk);
-		else
+			opt_stats = true;
+		} else
 #endif
 			skb = alloc_skb(0, GFP_ATOMIC);
 	} else {
@@ -3888,7 +3893,7 @@
 	else
 		skb->tstamp = ktime_get_real();
 
-	__skb_complete_tx_timestamp(skb, sk, tstype);
+	__skb_complete_tx_timestamp(skb, sk, tstype, opt_stats);
 }
 EXPORT_SYMBOL_GPL(__skb_tstamp_tx);
 
```
