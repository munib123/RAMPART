# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 259_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `259_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 11-51 of the vulnerable file.

 * FOR A PARTICULAR PURPOSE.
 *
 * Original code by Hannes Gredler (hannes@gredler.at)
 *  and Steinar Haug (sthaug@nethelp.no)
 */

/* \summary: Label Distribution Protocol (LDP) printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

#include "l2vpn.h"
#include "af.h"

/*
 * ldp common header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Version                      |         PDU Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         LDP Identifier                        |
 * +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct ldp_common_header {
    uint8_t version[2];
    uint8_t pdu_length[2];
    uint8_t lsr_id[4];
    uint8_t label_space[2];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,8 @@
 
 #include "l2vpn.h"
 #include "af.h"
+
+static const char tstr[] = " [|LDP]";
 
 /*
  * ldp common header
@@ -486,7 +488,7 @@
 	break;
 
     case LDP_TLV_FT_SESSION:
-	TLV_TCHECK(8);
+	TLV_TCHECK(12);
 	ft_flags = EXTRACT_16BITS(tptr);
 	ND_PRINT((ndo, "\n\t      Flags: [%sReconnect, %sSave State, %sAll-Label Protection, %s Checkpoint, %sRe-Learn State]",
 	       ft_flags&0x8000 ? "" : "No ",
@@ -494,6 +496,7 @@
 	       ft_flags&0x4 ? "" : "No ",
 	       ft_flags&0x2 ? "Sequence Numbered Label" : "All Labels",
 	       ft_flags&0x1 ? "" : "Don't "));
+	/* 16 bits (FT Flags) + 16 bits (Reserved) */
 	tptr+=4;
 	ui = EXTRACT_32BITS(tptr);
 	if (ui)
@@ -534,7 +537,7 @@
     return(tlv_len+4); /* Type & Length fields not included */
 
 trunc:
-    ND_PRINT((ndo, "\n\t\t packet exceeded snapshot"));
+    ND_PRINT((ndo, "%s", tstr));
     return 0;
 
 badtlv:
@@ -692,7 +695,7 @@
     }
     return pdu_len+4;
 trunc:
-    ND_PRINT((ndo, "\n\t\t packet exceeded snapshot"));
+    ND_PRINT((ndo, "%s", tstr));
     return 0;
 }
 
```
