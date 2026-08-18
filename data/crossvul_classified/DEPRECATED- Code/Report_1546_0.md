# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 1546_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1546_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 1201-1241 of the vulnerable file.

				  __func__);
			return;
		}

		neigh = dst_neigh_lookup(&rt->dst, &ipv6_hdr(skb)->saddr);
		if (neigh == NULL) {
			ND_PRINTK(0, err,
				  "RA: %s got default router without neighbour\n",
				  __func__);
			ip6_rt_put(rt);
			return;
		}
		neigh->flags |= NTF_ROUTER;
	} else if (rt) {
		rt->rt6i_flags = (rt->rt6i_flags & ~RTF_PREF_MASK) | RTF_PREF(pref);
	}

	if (rt)
		rt6_set_expires(rt, jiffies + (HZ * lifetime));
	if (ra_msg->icmph.icmp6_hop_limit) {
		in6_dev->cnf.hop_limit = ra_msg->icmph.icmp6_hop_limit;
		if (rt)
			dst_metric_set(&rt->dst, RTAX_HOPLIMIT,
				       ra_msg->icmph.icmp6_hop_limit);
	}

skip_defrtr:

	/*
	 *	Update Reachable Time and Retrans Timer
	 */

	if (in6_dev->nd_parms) {
		unsigned long rtime = ntohl(ra_msg->retrans_timer);

		if (rtime && rtime/1000 < MAX_SCHEDULE_TIMEOUT/HZ) {
			rtime = (rtime*HZ)/1000;
			if (rtime < HZ/10)
				rtime = HZ/10;
			NEIGH_VAR_SET(in6_dev->nd_parms, RETRANS_TIME, rtime);
			in6_dev->tstamp = jiffies;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1218,7 +1218,14 @@
 	if (rt)
 		rt6_set_expires(rt, jiffies + (HZ * lifetime));
 	if (ra_msg->icmph.icmp6_hop_limit) {
-		in6_dev->cnf.hop_limit = ra_msg->icmph.icmp6_hop_limit;
+		/* Only set hop_limit on the interface if it is higher than
+		 * the current hop_limit.
+		 */
+		if (in6_dev->cnf.hop_limit < ra_msg->icmph.icmp6_hop_limit) {
+			in6_dev->cnf.hop_limit = ra_msg->icmph.icmp6_hop_limit;
+		} else {
+			ND_PRINTK(2, warn, "RA: Got route advertisement with lower hop_limit than current\n");
+		}
 		if (rt)
 			dst_metric_set(&rt->dst, RTAX_HOPLIMIT,
 				       ra_msg->icmph.icmp6_hop_limit);
```
