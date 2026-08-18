# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2718_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2718_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 301-341 of the vulnerable file.

            }
        }
            break;
        }

        i += 2 + optlen;
    }
    return 0;
}

static int
dhcpv6_print(netdissect_options *ndo,
             const u_char *cp, u_int length, int indent)
{
    u_int i, t;
    const u_char *tlv, *value;
    uint16_t type, optlen;

    i = 0;
    while (i < length) {
        tlv = cp + i;
        type = EXTRACT_16BITS(tlv);
        optlen = EXTRACT_16BITS(tlv + 2);
        value = tlv + 4;

        ND_PRINT((ndo, "\n"));
        for (t = indent; t > 0; t--)
            ND_PRINT((ndo, "\t"));

        ND_PRINT((ndo, "%s", tok2str(dh6opt_str, "Unknown", type)));
        ND_PRINT((ndo," (%u)", optlen + 4 ));

        switch (type) {
            case DH6OPT_DNS_SERVERS:
            case DH6OPT_SNTP_SERVERS: {
                if (optlen % 16 != 0) {
                    ND_PRINT((ndo, " %s", istr));
                    return -1;
                }
                for (t = 0; t < optlen; t += 16)
                    ND_PRINT((ndo, " %s", ip6addr_string(ndo, value + t)));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -318,6 +318,8 @@
 
     i = 0;
     while (i < length) {
+        if (i + 4 > length)
+            return -1;
         tlv = cp + i;
         type = EXTRACT_16BITS(tlv);
         optlen = EXTRACT_16BITS(tlv + 2);
@@ -329,6 +331,8 @@
 
         ND_PRINT((ndo, "%s", tok2str(dh6opt_str, "Unknown", type)));
         ND_PRINT((ndo," (%u)", optlen + 4 ));
+        if (i + 4 + optlen > length)
+            return -1;
 
         switch (type) {
             case DH6OPT_DNS_SERVERS:
```
