# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1028_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1028_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

 * Original code by Hannes Gredler (hannes@gredler.at)
 * Support for LMP service discovery extensions (defined by OIF UNI 1.0)
 * added by Manu Pathak (mapathak@cisco.com), May 2005
 */

/* \summary: Link Management Protocol (LMP) printer */

/* specification: RFC 4204 */
/* OIF UNI 1.0: http://www.oiforum.com/public/documents/OIF-UNI-01.0.pdf */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"
#include "gmpls.h"

/*
 * LMP common header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Vers  |      (Reserved)       |    Flags      |    Msg Type   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          LMP Length           |          (Reserved)           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct lmp_common_header {
    uint8_t version_res[2];
    uint8_t flags;
    uint8_t msg_type;
    uint8_t length[2];
    uint8_t reserved[2];
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,8 @@
 #include "extract.h"
 #include "addrtoname.h"
 #include "gmpls.h"
+
+static const char tstr[] = " [|LMP]";
 
 /*
  * LMP common header
@@ -367,6 +369,7 @@
     } bw;
 
     while (total_subobj_len > 0 && hexdump == FALSE ) {
+	ND_TCHECK_16BITS(obj_tptr + offset);
 	subobj_type = EXTRACT_8BITS(obj_tptr + offset);
 	subobj_len  = EXTRACT_8BITS(obj_tptr + offset + 1);
 	ND_PRINT((ndo, "\n\t    Subobject, Type: %s (%u), Length: %u",
@@ -389,11 +392,13 @@
 	}
 	switch(subobj_type) {
 	case INT_SWITCHING_TYPE_SUBOBJ:
+	    ND_TCHECK_8BITS(obj_tptr + offset + 2);
 	    ND_PRINT((ndo, "\n\t      Switching Type: %s (%u)",
 		tok2str(gmpls_switch_cap_values,
 			"Unknown",
 			EXTRACT_8BITS(obj_tptr + offset + 2)),
 			EXTRACT_8BITS(obj_tptr + offset + 2)));
+	    ND_TCHECK_8BITS(obj_tptr + offset + 3);
 	    ND_PRINT((ndo, "\n\t      Encoding Type: %s (%u)",
 		tok2str(gmpls_encoding_values,
 			"Unknown",
@@ -403,11 +408,13 @@
 	    bw.i = EXTRACT_32BITS(obj_tptr+offset+4);
 	    ND_PRINT((ndo, "\n\t      Min Reservable Bandwidth: %.3f Mbps",
                 bw.f*8/1000000));
+	    ND_TCHECK_32BITS(obj_tptr + offset + 8);
 	    bw.i = EXTRACT_32BITS(obj_tptr+offset+8);
 	    ND_PRINT((ndo, "\n\t      Max Reservable Bandwidth: %.3f Mbps",
                 bw.f*8/1000000));
 	    break;
 	case WAVELENGTH_SUBOBJ:
+	    ND_TCHECK_32BITS(obj_tptr + offset + 4);
 	    ND_PRINT((ndo, "\n\t      Wavelength: %u",
 		EXTRACT_32BITS(obj_tptr+offset+4)));
 	    break;
@@ -1141,7 +1148,7 @@
     }
     return;
 trunc:
-    ND_PRINT((ndo, "\n\t\t packet exceeded snapshot"));
+    ND_PRINT((ndo, "%s", tstr));
 }
 /*
  * Local Variables:
```
