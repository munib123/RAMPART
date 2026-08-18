# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2723_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2723_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1317-1357 of the vulnerable file.

            li -= opli;
            tptr = pptr;

            ND_PRINT((ndo, "\n\t  %s Option #%u, length %u, value: ",
                   tok2str(esis_option_values,"Unknown",op),
                   op,
                   opli));

            switch (op) {

            case ESIS_OPTION_ES_CONF_TIME:
                if (opli == 2) {
                    ND_TCHECK2(*pptr, 2);
                    ND_PRINT((ndo, "%us", EXTRACT_16BITS(tptr)));
                } else
                    ND_PRINT((ndo, "(bad length)"));
                break;

            case ESIS_OPTION_PROTOCOLS:
                while (opli>0) {
                    ND_TCHECK(*pptr);
                    ND_PRINT((ndo, "%s (0x%02x)",
                           tok2str(nlpid_values,
                                   "unknown",
                                   *tptr),
                           *tptr));
                    if (opli>1) /* further NPLIDs ? - put comma */
                        ND_PRINT((ndo, ", "));
                    tptr++;
                    opli--;
                }
                break;

                /*
                 * FIXME those are the defined Options that lack a decoder
                 * you are welcome to contribute code ;-)
                 */

            case ESIS_OPTION_QOS_MAINTENANCE:
            case ESIS_OPTION_SECURITY:
            case ESIS_OPTION_PRIORITY:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1334,7 +1334,7 @@
 
             case ESIS_OPTION_PROTOCOLS:
                 while (opli>0) {
-                    ND_TCHECK(*pptr);
+                    ND_TCHECK(*tptr);
                     ND_PRINT((ndo, "%s (0x%02x)",
                            tok2str(nlpid_values,
                                    "unknown",
@@ -1367,7 +1367,7 @@
             pptr += opli;
         }
 trunc:
-	return;
+        ND_PRINT((ndo, "[|esis]"));
 }
 
 static void
```
