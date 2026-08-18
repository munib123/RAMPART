# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2696_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2696_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1114-1154 of the vulnerable file.

                break;
	case ICMP6_HADISCOV_REPLY:
		if (ndo->ndo_vflag) {
			const struct in6_addr *in6;
			const u_char *cp;

			ND_TCHECK(dp->icmp6_data16[0]);
			ND_PRINT((ndo,", id 0x%04x", EXTRACT_16BITS(&dp->icmp6_data16[0])));
			cp = (const u_char *)dp + length;
			in6 = (const struct in6_addr *)(dp + 1);
			for (; (const u_char *)in6 < cp; in6++) {
				ND_TCHECK(*in6);
				ND_PRINT((ndo,", %s", ip6addr_string(ndo, in6)));
			}
		}
		break;
	case ICMP6_MOBILEPREFIX_ADVERT:
		if (ndo->ndo_vflag) {
			ND_TCHECK(dp->icmp6_data16[0]);
			ND_PRINT((ndo,", id 0x%04x", EXTRACT_16BITS(&dp->icmp6_data16[0])));
			if (dp->icmp6_data16[1] & 0xc0)
				ND_PRINT((ndo," "));
			if (dp->icmp6_data16[1] & 0x80)
				ND_PRINT((ndo,"M"));
			if (dp->icmp6_data16[1] & 0x40)
				ND_PRINT((ndo,"O"));
#define MPADVLEN 8
			icmp6_opt_print(ndo, (const u_char *)dp + MPADVLEN,
					length - MPADVLEN);
		}
		break;
        case ND_RPL_MESSAGE:
                /* plus 4, because struct icmp6_hdr contains 4 bytes of icmp payload */
                rpl_print(ndo, dp, &dp->icmp6_data8[0], length-sizeof(struct icmp6_hdr)+4);
                break;
	default:
                ND_PRINT((ndo,", length %u", length));
                if (ndo->ndo_vflag <= 1)
                        print_unknown_data(ndo, bp,"\n\t", length);
                return;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1131,6 +1131,7 @@
 		if (ndo->ndo_vflag) {
 			ND_TCHECK(dp->icmp6_data16[0]);
 			ND_PRINT((ndo,", id 0x%04x", EXTRACT_16BITS(&dp->icmp6_data16[0])));
+			ND_TCHECK(dp->icmp6_data16[1]);
 			if (dp->icmp6_data16[1] & 0xc0)
 				ND_PRINT((ndo," "));
 			if (dp->icmp6_data16[1] & 0x80)
```
