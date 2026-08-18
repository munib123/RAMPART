# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 260_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `260_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 547-587 of the vulnerable file.


                (void)snprintf(buf+strlen(buf),sizeof(buf)-strlen(buf),", recv %s",
                         icmp_tstamp_print(EXTRACT_32BITS(&dp->icmp_rtime)));
                (void)snprintf(buf+strlen(buf),sizeof(buf)-strlen(buf),", xmit %s",
                         icmp_tstamp_print(EXTRACT_32BITS(&dp->icmp_ttime)));
                break;

	default:
		str = tok2str(icmp2str, "type-#%d", dp->icmp_type);
		break;
	}
	ND_PRINT((ndo, "ICMP %s, length %u", str, plen));
	if (ndo->ndo_vflag && !fragmented) { /* don't attempt checksumming if this is a frag */
		if (ND_TTEST2(*bp, plen)) {
			uint16_t sum;

			vec[0].ptr = (const uint8_t *)(const void *)dp;
			vec[0].len = plen;
			sum = in_cksum(vec, 1);
			if (sum != 0) {
				uint16_t icmp_sum = EXTRACT_16BITS(&dp->icmp_cksum);
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
		ndo->ndo_snaplen = ndo->ndo_snapend - bp;
                snapend_save = ndo->ndo_snapend;
		ND_TCHECK_16BITS(&ip->ip_len);
		ip_print(ndo, bp, EXTRACT_16BITS(&ip->ip_len));
                ndo->ndo_snapend = snapend_save;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -564,6 +564,7 @@
 			vec[0].len = plen;
 			sum = in_cksum(vec, 1);
 			if (sum != 0) {
+				ND_TCHECK_16BITS(&dp->icmp_cksum);
 				uint16_t icmp_sum = EXTRACT_16BITS(&dp->icmp_cksum);
 				ND_PRINT((ndo, " (wrong icmp cksum %x (->%x)!)",
 					     icmp_sum,
```
