# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5511_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5511_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 430-471 of the vulnerable file.

	 */

	if (addr_type & IPV6_ADDR_MULTICAST || skb->pkt_type != PACKET_HOST) {
		if (type != ICMPV6_PKT_TOOBIG &&
		    !(type == ICMPV6_PARAMPROB &&
		      code == ICMPV6_UNK_OPTION &&
		      (opt_unrec(skb, info))))
			return;

		saddr = NULL;
	}

	addr_type = ipv6_addr_type(&hdr->saddr);

	/*
	 *	Source addr check
	 */

	if (__ipv6_addr_needs_scope_id(addr_type))
		iif = skb->dev->ifindex;
	else
		iif = l3mdev_master_ifindex(skb_dst(skb)->dev);

	/*
	 *	Must not send error if the source does not uniquely
	 *	identify a single node (RFC2463 Section 2.4).
	 *	We check unspecified / multicast addresses here,
	 *	and anycast addresses will be checked later.
	 */
	if ((addr_type == IPV6_ADDR_ANY) || (addr_type & IPV6_ADDR_MULTICAST)) {
		net_dbg_ratelimited("icmp6_send: addr_any/mcast source [%pI6c > %pI6c]\n",
				    &hdr->saddr, &hdr->daddr);
		return;
	}

	/*
	 *	Never answer to a ICMP packet.
	 */
	if (is_ineligible(skb)) {
		net_dbg_ratelimited("icmp6_send: no reply to icmp error [%pI6c > %pI6c]\n",
				    &hdr->saddr, &hdr->daddr);
		return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -447,8 +447,10 @@
 
 	if (__ipv6_addr_needs_scope_id(addr_type))
 		iif = skb->dev->ifindex;
-	else
-		iif = l3mdev_master_ifindex(skb_dst(skb)->dev);
+	else {
+		dst = skb_dst(skb);
+		iif = l3mdev_master_ifindex(dst ? dst->dev : skb->dev);
+	}
 
 	/*
 	 *	Must not send error if the source does not uniquely
```
