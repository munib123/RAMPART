# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5006_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5006_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 905-945 of the vulnerable file.


	if (ifa->ifa_flags & IFA_F_SECONDARY) {
		prim = inet_ifa_byprefix(in_dev, any, ifa->ifa_mask);
		if (!prim) {
			pr_warn("%s: bug: prim == NULL\n", __func__);
			return;
		}
		if (iprim && iprim != prim) {
			pr_warn("%s: bug: iprim != prim\n", __func__);
			return;
		}
	} else if (!ipv4_is_zeronet(any) &&
		   (any != ifa->ifa_local || ifa->ifa_prefixlen < 32)) {
		if (!(ifa->ifa_flags & IFA_F_NOPREFIXROUTE))
			fib_magic(RTM_DELROUTE,
				  dev->flags & IFF_LOOPBACK ? RTN_LOCAL : RTN_UNICAST,
				  any, ifa->ifa_prefixlen, prim);
		subnet = 1;
	}

	/* Deletion is more complicated than add.
	 * We should take care of not to delete too much :-)
	 *
	 * Scan address list to be sure that addresses are really gone.
	 */

	for (ifa1 = in_dev->ifa_list; ifa1; ifa1 = ifa1->ifa_next) {
		if (ifa1 == ifa) {
			/* promotion, keep the IP */
			gone = 0;
			continue;
		}
		/* Ignore IFAs from our subnet */
		if (iprim && ifa1->ifa_mask == iprim->ifa_mask &&
		    inet_ifa_match(ifa1->ifa_address, iprim))
			continue;

		/* Ignore ifa1 if it uses different primary IP (prefsrc) */
		if (ifa1->ifa_flags & IFA_F_SECONDARY) {
			/* Another address from our subnet? */
			if (ifa1->ifa_mask == prim->ifa_mask &&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -922,6 +922,9 @@
 		subnet = 1;
 	}
 
+	if (in_dev->dead)
+		goto no_promotions;
+
 	/* Deletion is more complicated than add.
 	 * We should take care of not to delete too much :-)
 	 *
@@ -997,6 +1000,7 @@
 		}
 	}
 
+no_promotions:
 	if (!(ok & BRD_OK))
 		fib_magic(RTM_DELROUTE, RTN_BROADCAST, ifa->ifa_broadcast, 32, prim);
 	if (subnet && ifa->ifa_prefixlen < 31) {
```
