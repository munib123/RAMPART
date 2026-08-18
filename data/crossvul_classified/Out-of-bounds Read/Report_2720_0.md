# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2720_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2720_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 253-293 of the vulnerable file.

        }
        if (print)
            safeputs(ndo, cp+length, lab_length);
        length += lab_length;
    }
    if (print)
        ND_PRINT((ndo, "[|DNS]"));
    return -1;
}

static int
dhcpv4_print(netdissect_options *ndo,
             const u_char *cp, u_int length, int indent)
{
    u_int i, t;
    const u_char *tlv, *value;
    uint8_t type, optlen;

    i = 0;
    while (i < length) {
        tlv = cp + i;
        type = (uint8_t)tlv[0];
        optlen = (uint8_t)tlv[1];
        value = tlv + 2;

        ND_PRINT((ndo, "\n"));
        for (t = indent; t > 0; t--)
            ND_PRINT((ndo, "\t"));

        ND_PRINT((ndo, "%s", tok2str(dh4opt_str, "Unknown", type)));
        ND_PRINT((ndo," (%u)", optlen + 2 ));

        switch (type) {
        case DH4OPT_DNS_SERVERS:
        case DH4OPT_NTP_SERVERS: {
            if (optlen < 4 || optlen % 4 != 0) {
                return -1;
            }
            for (t = 0; t < optlen; t += 4)
                ND_PRINT((ndo, " %s", ipaddr_string(ndo, value + t)));
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -270,6 +270,8 @@
 
     i = 0;
     while (i < length) {
+        if (i + 2 > length)
+            return -1;
         tlv = cp + i;
         type = (uint8_t)tlv[0];
         optlen = (uint8_t)tlv[1];
@@ -281,6 +283,8 @@
 
         ND_PRINT((ndo, "%s", tok2str(dh4opt_str, "Unknown", type)));
         ND_PRINT((ndo," (%u)", optlen + 2 ));
+        if (i + 2 + optlen > length)
+            return -1;
 
         switch (type) {
         case DH4OPT_DNS_SERVERS:
```
