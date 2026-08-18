# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 268_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `268_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 463-503 of the vulnerable file.

            break;

        case MESSAGE_NH: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, " nh"));
            else {
                int rc;
                u_char nh[16];
                ND_PRINT((ndo, "\n\tNext Hop"));
                if(len < 2) goto invalid;
                rc = network_address(message[2], message + 4, len - 2, nh);
                if(rc < 0) goto invalid;
                ND_PRINT((ndo, " %s", format_address(ndo, nh)));
            }
        }
            break;

        case MESSAGE_UPDATE: {
            if (!ndo->ndo_vflag) {
                ND_PRINT((ndo, " update"));
                if(len < 1)
                    ND_PRINT((ndo, "/truncated"));
                else
                    ND_PRINT((ndo, "%s%s%s",
                           (message[3] & 0x80) ? "/prefix": "",
                           (message[3] & 0x40) ? "/id" : "",
                           (message[3] & 0x3f) ? "/unknown" : ""));
            } else {
                u_short interval, seqno, metric;
                u_char plen;
                int rc;
                u_char prefix[16];
                ND_PRINT((ndo, "\n\tUpdate"));
                if(len < 10) goto invalid;
                plen = message[4] + (message[2] == 1 ? 96 : 0);
                rc = network_prefix(message[2], message[4], message[5],
                                    message + 12,
                                    message[2] == 1 ? v4_prefix : v6_prefix,
                                    len - 10, prefix);
                if(rc < 0) goto invalid;
                interval = EXTRACT_16BITS(message + 6);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -480,7 +480,7 @@
         case MESSAGE_UPDATE: {
             if (!ndo->ndo_vflag) {
                 ND_PRINT((ndo, " update"));
-                if(len < 1)
+                if(len < 10)
                     ND_PRINT((ndo, "/truncated"));
                 else
                     ND_PRINT((ndo, "%s%s%s",
```
