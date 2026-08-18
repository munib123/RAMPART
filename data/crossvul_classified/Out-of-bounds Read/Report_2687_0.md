# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2687_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2687_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 564-604 of the vulnerable file.

			vec[0].len = plen;
			sum = in_cksum(vec, 1);
			if (sum != 0) {
				icmp_sum = EXTRACT_16BITS(&dp->icmp_cksum);
				ND_PRINT((ndo, " (wrong icmp cksum %x (->%x)!)",
					     icmp_sum,
					     in_cksum_shouldbe(icmp_sum, sum)));
			}
		}
	}

        /*
         * print the remnants of the IP packet.
         * save the snaplength as this may get overidden in the IP printer.
         */
	if (ndo->ndo_vflag >= 1 && ICMP_ERRTYPE(dp->icmp_type)) {
		bp += 8;
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
            if (!ext_dp->icmp_length &&
                ND_TTEST2(ext_dp->icmp_ext_version_res, plen - ICMP_EXTD_MINLEN)) {
                vec[0].ptr = (const uint8_t *)(const void *)&ext_dp->icmp_ext_version_res;
                vec[0].len = plen - ICMP_EXTD_MINLEN;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -581,6 +581,7 @@
 		ND_PRINT((ndo, "\n\t"));
 		ip = (const struct ip *)bp;
                 snapend_save = ndo->ndo_snapend;
+		ND_TCHECK_16BITS(&ip->ip_len);
 		ip_print(ndo, bp, EXTRACT_16BITS(&ip->ip_len));
                 ndo->ndo_snapend = snapend_save;
 	}
```
