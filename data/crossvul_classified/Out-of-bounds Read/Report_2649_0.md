# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2649_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2649_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 14-54 of the vulnerable file.

 * FOR A PARTICULAR PURPOSE.
 */

/* \summary: Enhanced Interior Gateway Routing Protocol (EIGRP) printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <string.h>

#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

/*
 * packet format documented at
 * http://www.rhyshaden.com/eigrp.htm
 */

struct eigrp_common_header {
    uint8_t version;
    uint8_t opcode;
    uint8_t checksum[2];
    uint8_t flags[4];
    uint8_t seq[4];
    uint8_t ack[4];
    uint8_t asn[4];
};

#define	EIGRP_VERSION                        2

#define	EIGRP_OPCODE_UPDATE                  1
#define	EIGRP_OPCODE_QUERY                   3
#define	EIGRP_OPCODE_REPLY                   4
#define	EIGRP_OPCODE_HELLO                   5
#define	EIGRP_OPCODE_IPXSAP                  6
#define	EIGRP_OPCODE_PROBE                   7

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,7 @@
 /*
  * packet format documented at
  * http://www.rhyshaden.com/eigrp.htm
+ * RFC 7868
  */
 
 struct eigrp_common_header {
@@ -246,6 +247,12 @@
 
     /* ok they seem to want to know everything - lets fully decode it */
 
+    if (len < sizeof(struct eigrp_common_header)) {
+        ND_PRINT((ndo, "EIGRP %s, length: %u (too short, < %u)",
+               tok2str(eigrp_opcode_values, "unknown (%u)",eigrp_com_header->opcode),
+               len, (u_int) sizeof(struct eigrp_common_header)));
+        return;
+    }
     tlen=len-sizeof(struct eigrp_common_header);
 
     /* FIXME print other header info */
@@ -286,6 +293,11 @@
                eigrp_tlv_type,
                eigrp_tlv_len));
 
+        if (eigrp_tlv_len < sizeof(struct eigrp_tlv_header)) {
+                ND_PRINT((ndo, " (too short, < %u)",
+                        (u_int) sizeof(struct eigrp_tlv_header)));
+                break;
+        }
         tlv_tptr=tptr+sizeof(struct eigrp_tlv_header);
         tlv_tlen=eigrp_tlv_len-sizeof(struct eigrp_tlv_header);
 
@@ -296,6 +308,11 @@
 
         case EIGRP_TLV_GENERAL_PARM:
             tlv_ptr.eigrp_tlv_general_parm = (const struct eigrp_tlv_general_parm_t *)tlv_tptr;
+            if (tlv_tlen < sizeof(*tlv_ptr.eigrp_tlv_general_parm)) {
+                ND_PRINT((ndo, " (too short, < %u)",
+                    (u_int) (sizeof(struct eigrp_tlv_header) + sizeof(*tlv_ptr.eigrp_tlv_general_parm))));
+                break;
+            }
 
             ND_PRINT((ndo, "\n\t    holdtime: %us, k1 %u, k2 %u, k3 %u, k4 %u, k5 %u",
                    EXTRACT_16BITS(tlv_ptr.eigrp_tlv_general_parm->holdtime),
@@ -308,6 +325,11 @@
 
         case EIGRP_TLV_SW_VERSION:
             tlv_ptr.eigrp_tlv_sw_version = (const struct eigrp_tlv_sw_version_t *)tlv_tptr;
+            if (tlv_tlen < sizeof(*tlv_ptr.eigrp_tlv_sw_version)) {
+                ND_PRINT((ndo, " (too short, < %u)",
+                    (u_int) (sizeof(struct eigrp_tlv_header) + sizeof(*tlv_ptr.eigrp_tlv_sw_version))));
+                break;
+            }
 
             ND_PRINT((ndo, "\n\t    IOS version: %u.%u, EIGRP version %u.%u",
                    tlv_ptr.eigrp_tlv_sw_version->ios_major,
@@ -318,6 +340,11 @@
 
         case EIGRP_TLV_IP_INT:
             tlv_ptr.eigrp_tlv_ip_int = (const struct eigrp_tlv_ip_int_t *)tlv_tptr;
+            if (tlv_tlen < sizeof(*tlv_ptr.eigrp_tlv_ip_int)) {
+                ND_PRINT((ndo, " (too short, < %u)",
+                    (u_int) (sizeof(struct eigrp_tlv_header) + sizeof(*tlv_ptr.eigrp_tlv_ip_int))));
+                break;
+            }
 
             bit_length = tlv_ptr.eigrp_tlv_ip_int->plen;
             if (bit_length > 32) {
@@ -347,6 +374,11 @@
 
         case EIGRP_TLV_IP_EXT:
             tlv_ptr.eigrp_tlv_ip_ext = (const struct eigrp_tlv_ip_ext_t *)tlv_tptr;
+            if (tlv_tlen < sizeof(*tlv_ptr.eigrp_tlv_ip_ext)) {
+                ND_PRINT((ndo, " (too short, < %u)",
+                    (u_int) (sizeof(struct eigrp_tlv_header) + sizeof(*tlv_ptr.eigrp_tlv_ip_ext))));
+                break;
+            }
 
             bit_length = tlv_ptr.eigrp_tlv_ip_ext->plen;
             if (bit_length > 32) {
@@ -384,6 +416,11 @@
 
         case EIGRP_TLV_AT_CABLE_SETUP:
             tlv_ptr.eigrp_tlv_at_cable_setup = (const struct eigrp_tlv_at_cable_setup_t *)tlv_tptr;
+            if (tlv_tlen < sizeof(*tlv_ptr.eigrp_tlv_at_cable_setup)) {
+                ND_PRINT((ndo, " (too short, < %u)",
+                    (u_int) (sizeof(struct eigrp_tlv_header) + sizeof(*tlv_ptr.eigrp_tlv_at_cable_setup))));
+                break;
+            }
 
             ND_PRINT((ndo, "\n\t    Cable-range: %u-%u, Router-ID %u",
                    EXTRACT_16BITS(&tlv_ptr.eigrp_tlv_at_cable_setup->cable_start),
@@ -393,6 +430,11 @@
 
         case EIGRP_TLV_AT_INT:
             tlv_ptr.eigrp_tlv_at_int = (const struct eigrp_tlv_at_int_t *)tlv_tptr;
+            if (tlv_tlen < sizeof(*tlv_ptr.eigrp_tlv_at_int)) {
+                ND_PRINT((ndo, " (too short, < %u)",
+                    (u_int) (sizeof(struct eigrp_tlv_header) + sizeof(*tlv_ptr.eigrp_tlv_at_int))));
+                break;
+            }
 
             ND_PRINT((ndo, "\n\t     Cable-Range: %u-%u, nexthop: ",
                    EXTRACT_16BITS(&tlv_ptr.eigrp_tlv_at_int->cable_start),
@@ -416,6 +458,11 @@
 
         case EIGRP_TLV_AT_EXT:
             tlv_ptr.eigrp_tlv_at_ext = (const struct eigrp_tlv_at_ext_t *)tlv_tptr;
+            if (tlv_tlen < sizeof(*tlv_ptr.eigrp_tlv_at_ext)) {
+                ND_PRINT((ndo, " (too short, < %u)",
+                    (u_int) (sizeof(struct eigrp_tlv_header) + sizeof(*tlv_ptr.eigrp_tlv_at_ext))));
+                break;
+            }
 
             ND_PRINT((ndo, "\n\t     Cable-Range: %u-%u, nexthop: ",
                    EXTRACT_16BITS(&tlv_ptr.eigrp_tlv_at_ext->cable_start),
```
