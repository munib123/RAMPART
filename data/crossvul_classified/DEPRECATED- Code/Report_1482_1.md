# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1482_1
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1482_1`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 112-152 of the vulnerable file.

	mtu = ip_dst_mtu_maybe_forward(&rt->dst, true);
	if (!ip_may_fragment(skb) && ip_exceeds_mtu(skb, mtu)) {
		IP_INC_STATS(dev_net(rt->dst.dev), IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(mtu));
		goto drop;
	}

	/* We are about to mangle packet. Copy it! */
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->dst.dev)+rt->dst.header_len))
		goto drop;
	iph = ip_hdr(skb);

	/* Decrease ttl after skb cow done */
	ip_decrease_ttl(iph);

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr && !skb_sec_path(skb))
		ip_rt_send_redirect(skb);

	skb->priority = rt_tos2priority(iph->tos);

	return NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD, skb, skb->dev,
		       rt->dst.dev, ip_forward_finish);

sr_failed:
	/*
	 *	Strict routing permits no gatewaying
	 */
	 icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
	 goto drop;

too_many_hops:
	/* Tell the sender its packet died... */
	IP_INC_STATS_BH(dev_net(skb_dst(skb)->dev), IPSTATS_MIB_INHDRERRORS);
	icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
drop:
	kfree_skb(skb);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,7 +129,8 @@
 	 *	We now generate an ICMP HOST REDIRECT giving the route
 	 *	we calculated.
 	 */
-	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr && !skb_sec_path(skb))
+	if (IPCB(skb)->flags & IPSKB_DOREDIRECT && !opt->srr &&
+	    !skb_sec_path(skb))
 		ip_rt_send_redirect(skb);
 
 	skb->priority = rt_tos2priority(iph->tos);
```
