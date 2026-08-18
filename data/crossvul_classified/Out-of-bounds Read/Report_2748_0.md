# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2748_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2748_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1418-1459 of the vulnerable file.

				ND_PRINT((ndo," len=%d [bad: < 8]", len));
			else {
				mask = data + sizeof(struct in_addr);
				ND_PRINT((ndo," len=%d %s/%u.%u.%u.%u", len,
					  ipaddr_string(ndo, data),
					  mask[0], mask[1], mask[2], mask[3]));
			}
			len = 0;
			break;
		    }
		case IPSECDOI_ID_IPV6_ADDR:
			if (len < 16)
				ND_PRINT((ndo," len=%d [bad: < 16]", len));
			else
				ND_PRINT((ndo," len=%d %s", len, ip6addr_string(ndo, data)));
			len = 0;
			break;
		case IPSECDOI_ID_IPV6_ADDR_SUBNET:
		    {
			const u_char *mask;
			if (len < 20)
				ND_PRINT((ndo," len=%d [bad: < 20]", len));
			else {
				mask = (const u_char *)(data + sizeof(struct in6_addr));
				/*XXX*/
				ND_PRINT((ndo," len=%d %s/0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", len,
					  ip6addr_string(ndo, data),
					  mask[0], mask[1], mask[2], mask[3],
					  mask[4], mask[5], mask[6], mask[7],
					  mask[8], mask[9], mask[10], mask[11],
					  mask[12], mask[13], mask[14], mask[15]));
			}
			len = 0;
			break;
		    }
		case IPSECDOI_ID_IPV4_ADDR_RANGE:
			if (len < 8)
				ND_PRINT((ndo," len=%d [bad: < 8]", len));
			else {
				ND_PRINT((ndo," len=%d %s-%s", len,
					  ipaddr_string(ndo, data),
					  ipaddr_string(ndo, data + sizeof(struct in_addr))));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1435,8 +1435,8 @@
 		case IPSECDOI_ID_IPV6_ADDR_SUBNET:
 		    {
 			const u_char *mask;
-			if (len < 20)
-				ND_PRINT((ndo," len=%d [bad: < 20]", len));
+			if (len < 32)
+				ND_PRINT((ndo," len=%d [bad: < 32]", len));
 			else {
 				mask = (const u_char *)(data + sizeof(struct in6_addr));
 				/*XXX*/
```
