# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 329_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `329_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 212-252 of the vulnerable file.

        u_int plen;

        plen = prefix[0]-96;
        if (32 < plen)
            return -1;
        max_length -= 1;

        memset(&addr, 0, sizeof(addr));
        plenbytes = (plen + 7) / 8;
        if (max_length < (u_int)plenbytes + IPV4_MAPPED_HEADING_LEN)
            return -3;
        memcpy(&addr, &prefix[1 + IPV4_MAPPED_HEADING_LEN], plenbytes);
        if (plen % 8) {
		((u_char *)&addr)[plenbytes - 1] &=
			((0xff00 >> (plen % 8)) & 0xff);
	}
	snprintf(buf, sizeof(buf), "%s/%d", ipaddr_string(ndo, &addr), plen);
        plenbytes += 1 + IPV4_MAPPED_HEADING_LEN;
    } else {
        plenbytes = decode_prefix6(ndo, prefix, max_length, buf, sizeof(buf));
    }

    ND_PRINT((ndo, "%s", buf));
    return plenbytes;
}

static int
print_dns_label(netdissect_options *ndo,
                const u_char *cp, u_int max_length, int print)
{
    u_int length = 0;
    while (length < max_length) {
        u_int lab_length = cp[length++];
        if (lab_length == 0)
            return (int)length;
        if (length > 1 && print)
            safeputchar(ndo, '.');
        if (length+lab_length > max_length) {
            if (print)
                safeputs(ndo, cp+length, max_length-length);
            break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -229,6 +229,8 @@
         plenbytes += 1 + IPV4_MAPPED_HEADING_LEN;
     } else {
         plenbytes = decode_prefix6(ndo, prefix, max_length, buf, sizeof(buf));
+        if (plenbytes < 0)
+            return plenbytes;
     }
 
     ND_PRINT((ndo, "%s", buf));
```
