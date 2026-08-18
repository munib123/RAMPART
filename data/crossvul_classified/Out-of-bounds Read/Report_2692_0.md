# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2692_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2692_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 501-541 of the vulnerable file.

			}

			ND_PRINT((ndo, ")"));
			break;
		case DH6OPT_RAPID_COMMIT: /* nothing todo */
			ND_PRINT((ndo, ")"));
			break;
		case DH6OPT_INTERFACE_ID:
		case DH6OPT_SUBSCRIBER_ID:
			/*
			 * Since we cannot predict the encoding, print hex dump
			 * at most 10 characters.
			 */
			tp = (const u_char *)(dh6o + 1);
			ND_PRINT((ndo, " "));
			for (i = 0; i < optlen && i < 10; i++)
				ND_PRINT((ndo, "%02x", tp[i]));
			ND_PRINT((ndo, "...)"));
			break;
		case DH6OPT_RECONF_MSG:
			tp = (const u_char *)(dh6o + 1);
			switch (*tp) {
			case DH6_RENEW:
				ND_PRINT((ndo, " for renew)"));
				break;
			case DH6_INFORM_REQ:
				ND_PRINT((ndo, " for inf-req)"));
				break;
			default:
				ND_PRINT((ndo, " for ?\?\?(%02x))", *tp));
				break;
			}
			break;
		case DH6OPT_RECONF_ACCEPT: /* nothing todo */
			ND_PRINT((ndo, ")"));
			break;
		case DH6OPT_SIP_SERVER_A:
		case DH6OPT_DNS_SERVERS:
		case DH6OPT_SNTP_SERVERS:
		case DH6OPT_NIS_SERVERS:
		case DH6OPT_NISP_SERVERS:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -518,6 +518,10 @@
 			ND_PRINT((ndo, "...)"));
 			break;
 		case DH6OPT_RECONF_MSG:
+			if (optlen != 1) {
+				ND_PRINT((ndo, " ?)"));
+				break;
+			}
 			tp = (const u_char *)(dh6o + 1);
 			switch (*tp) {
 			case DH6_RENEW:
```
