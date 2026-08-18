# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3575_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3575_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 863-903 of the vulnerable file.

		/* cancel the interface change timer */
		in_dev->mr_ifc_count = 0;
		if (del_timer(&in_dev->mr_ifc_timer))
			__in_dev_put(in_dev);
		/* clear deleted report items */
		igmpv3_clear_delrec(in_dev);
	} else if (len < 12) {
		return;	/* ignore bogus packet; freed by caller */
	} else if (IGMP_V1_SEEN(in_dev)) {
		/* This is a v3 query with v1 queriers present */
		max_delay = IGMP_Query_Response_Interval;
		group = 0;
	} else if (IGMP_V2_SEEN(in_dev)) {
		/* this is a v3 query with v2 queriers present;
		 * Interpretation of the max_delay code is problematic here.
		 * A real v2 host would use ih_code directly, while v3 has a
		 * different encoding. We use the v3 encoding as more likely
		 * to be intended in a v3 query.
		 */
		max_delay = IGMPV3_MRC(ih3->code)*(HZ/IGMP_TIMER_SCALE);
	} else { /* v3 */
		if (!pskb_may_pull(skb, sizeof(struct igmpv3_query)))
			return;

		ih3 = igmpv3_query_hdr(skb);
		if (ih3->nsrcs) {
			if (!pskb_may_pull(skb, sizeof(struct igmpv3_query)
					   + ntohs(ih3->nsrcs)*sizeof(__be32)))
				return;
			ih3 = igmpv3_query_hdr(skb);
		}

		max_delay = IGMPV3_MRC(ih3->code)*(HZ/IGMP_TIMER_SCALE);
		if (!max_delay)
			max_delay = 1;	/* can't mod w/ 0 */
		in_dev->mr_maxdelay = max_delay;
		if (ih3->qrv)
			in_dev->mr_qrv = ih3->qrv;
		if (!group) { /* general query */
			if (ih3->nsrcs)
				return;	/* no sources allowed */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -880,6 +880,8 @@
 		 * to be intended in a v3 query.
 		 */
 		max_delay = IGMPV3_MRC(ih3->code)*(HZ/IGMP_TIMER_SCALE);
+		if (!max_delay)
+			max_delay = 1;	/* can't mod w/ 0 */
 	} else { /* v3 */
 		if (!pskb_may_pull(skb, sizeof(struct igmpv3_query)))
 			return;
```
