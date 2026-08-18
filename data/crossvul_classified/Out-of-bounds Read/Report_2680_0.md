# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2680_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2680_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1350-1390 of the vulnerable file.

            l2info->caplen -= l2info->cookie_len;

            if (ndo->ndo_eflag)
                ND_PRINT((ndo, "%s-PIC, cookie-len %u",
                       lp->s,
                       l2info->cookie_len));

            if (l2info->cookie_len > 0) {
                ND_TCHECK2(p[0], l2info->cookie_len);
                if (ndo->ndo_eflag)
                    ND_PRINT((ndo, ", cookie 0x"));
                for (idx = 0; idx < l2info->cookie_len; idx++) {
                    l2info->cookie[idx] = p[idx]; /* copy cookie data */
                    if (ndo->ndo_eflag) ND_PRINT((ndo, "%02x", p[idx]));
                }
            }

            if (ndo->ndo_eflag) ND_PRINT((ndo, ": ")); /* print demarc b/w L2/L3*/


            l2info->proto = EXTRACT_16BITS(p+l2info->cookie_len);
            break;
        }
        ++lp;
    }
    p+=l2info->cookie_len;

    /* DLT_ specific parsing */
    switch(l2info->pictype) {
#ifdef DLT_JUNIPER_MLPPP
    case DLT_JUNIPER_MLPPP:
        switch (l2info->cookie_type) {
        case LS_COOKIE_ID:
            l2info->bundle = l2info->cookie[1];
            break;
        case AS_COOKIE_ID:
            l2info->bundle = (EXTRACT_16BITS(&l2info->cookie[6])>>3)&0xfff;
            l2info->proto = (l2info->cookie[5])&JUNIPER_LSQ_L3_PROTO_MASK;
            break;
        default:
            l2info->bundle = l2info->cookie[0];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1367,6 +1367,7 @@
             if (ndo->ndo_eflag) ND_PRINT((ndo, ": ")); /* print demarc b/w L2/L3*/
 
 
+            ND_TCHECK_16BITS(p+l2info->cookie_len);
             l2info->proto = EXTRACT_16BITS(p+l2info->cookie_len);
             break;
         }
```
