# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3520_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3520_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 232-274 of the vulnerable file.


	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	iph = ip_hdr(skb);
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto inhdr_error;

	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	if (pskb_trim_rcsum(skb, len)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	/* Zero out the CB buffer if no options present */
	if (iph->ihl == 5) {
		memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
		return 0;
	}

	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);
	if (ip_options_compile(dev_net(dev), opt, skb))
		goto inhdr_error;

	/* Check correct handling of SRR option */
	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);
		if (in_dev && !IN_DEV_SOURCE_ROUTE(in_dev))
			goto drop;

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return 0;

inhdr_error:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -249,11 +249,9 @@
 		goto drop;
 	}
 
-	/* Zero out the CB buffer if no options present */
-	if (iph->ihl == 5) {
-		memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
+	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
+	if (iph->ihl == 5)
 		return 0;
-	}
 
 	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);
 	if (ip_options_compile(dev_net(dev), opt, skb))
```
