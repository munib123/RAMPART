# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2641_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2641_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 581-621 of the vulnerable file.

		ND_PRINT((ndo, "\n\t"));
		ip = (const struct ip *)bp;
                snapend_save = ndo->ndo_snapend;
		ip_print(ndo, bp, EXTRACT_16BITS(&ip->ip_len));
                ndo->ndo_snapend = snapend_save;
	}

        /*
         * Attempt to decode the MPLS extensions only for some ICMP types.
         */
        if (ndo->ndo_vflag >= 1 && plen > ICMP_EXTD_MINLEN && ICMP_MPLS_EXT_TYPE(dp->icmp_type)) {

            ND_TCHECK(*ext_dp);

            /*
             * Check first if the mpls extension header shows a non-zero length.
             * If the length field is not set then silently verify the checksum
             * to check if an extension header is present. This is expedient,
             * however not all implementations set the length field proper.
             */
            if (!ext_dp->icmp_length) {
                vec[0].ptr = (const uint8_t *)(const void *)&ext_dp->icmp_ext_version_res;
                vec[0].len = plen - ICMP_EXTD_MINLEN;
                if (in_cksum(vec, 1)) {
                    return;
                }
            }

            ND_PRINT((ndo, "\n\tMPLS extension v%u",
                   ICMP_MPLS_EXT_EXTRACT_VERSION(*(ext_dp->icmp_ext_version_res))));

            /*
             * Sanity checking of the header.
             */
            if (ICMP_MPLS_EXT_EXTRACT_VERSION(*(ext_dp->icmp_ext_version_res)) !=
                ICMP_MPLS_EXT_VERSION) {
                ND_PRINT((ndo, " packet not supported"));
                return;
            }

            hlen = plen - ICMP_EXTD_MINLEN;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -598,7 +598,8 @@
              * to check if an extension header is present. This is expedient,
              * however not all implementations set the length field proper.
              */
-            if (!ext_dp->icmp_length) {
+            if (!ext_dp->icmp_length &&
+                ND_TTEST2(ext_dp->icmp_ext_version_res, plen - ICMP_EXTD_MINLEN)) {
                 vec[0].ptr = (const uint8_t *)(const void *)&ext_dp->icmp_ext_version_res;
                 vec[0].len = plen - ICMP_EXTD_MINLEN;
                 if (in_cksum(vec, 1)) {
@@ -619,12 +620,14 @@
             }
 
             hlen = plen - ICMP_EXTD_MINLEN;
-            vec[0].ptr = (const uint8_t *)(const void *)&ext_dp->icmp_ext_version_res;
-            vec[0].len = hlen;
-            ND_PRINT((ndo, ", checksum 0x%04x (%scorrect), length %u",
-                   EXTRACT_16BITS(ext_dp->icmp_ext_checksum),
-                   in_cksum(vec, 1) ? "in" : "",
-                   hlen));
+            if (ND_TTEST2(ext_dp->icmp_ext_version_res, hlen)) {
+                vec[0].ptr = (const uint8_t *)(const void *)&ext_dp->icmp_ext_version_res;
+                vec[0].len = hlen;
+                ND_PRINT((ndo, ", checksum 0x%04x (%scorrect), length %u",
+                       EXTRACT_16BITS(ext_dp->icmp_ext_checksum),
+                       in_cksum(vec, 1) ? "in" : "",
+                       hlen));
+            }
 
             hlen -= 4; /* subtract common header size */
             obj_tptr = (const uint8_t *)ext_dp->icmp_ext_data;
```
