# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2721_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2721_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 9-49 of the vulnerable file.

 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * Original code by Carles Kishimoto <Carles.Kishimoto@bsc.es>
 */

/* \summary: Cisco VLAN Query Protocol (VQP) printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

#define VQP_VERSION            		1
#define VQP_EXTRACT_VERSION(x) ((x)&0xFF)

/*
 * VQP common header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Constant    | Packet type   |  Error Code   |    nitems     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Packet Sequence Number (4 bytes)               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct vqp_common_header_t {
    uint8_t version;
    uint8_t msg_type;
    uint8_t error_code;
    uint8_t nitems;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,6 +26,7 @@
 #include "netdissect.h"
 #include "extract.h"
 #include "addrtoname.h"
+#include "ether.h"
 
 #define VQP_VERSION            		1
 #define VQP_EXTRACT_VERSION(x) ((x)&0xFF)
@@ -105,13 +106,15 @@
     const u_char *tptr;
     uint16_t vqp_obj_len;
     uint32_t vqp_obj_type;
-    int tlen;
+    u_int tlen;
     uint8_t nitems;
 
     tptr=pptr;
     tlen = len;
     vqp_common_header = (const struct vqp_common_header_t *)pptr;
     ND_TCHECK(*vqp_common_header);
+    if (sizeof(struct vqp_common_header_t) > tlen)
+        goto trunc;
 
     /*
      * Sanity checking of the header.
@@ -151,6 +154,9 @@
     while (nitems > 0 && tlen > 0) {
 
         vqp_obj_tlv = (const struct vqp_obj_tlv_t *)tptr;
+        ND_TCHECK(*vqp_obj_tlv);
+        if (sizeof(struct vqp_obj_tlv_t) > tlen)
+            goto trunc;
         vqp_obj_type = EXTRACT_32BITS(vqp_obj_tlv->obj_type);
         vqp_obj_len = EXTRACT_16BITS(vqp_obj_tlv->obj_length);
         tptr+=sizeof(struct vqp_obj_tlv_t);
@@ -167,9 +173,13 @@
 
         /* did we capture enough for fully decoding the object ? */
         ND_TCHECK2(*tptr, vqp_obj_len);
+        if (vqp_obj_len > tlen)
+            goto trunc;
 
         switch(vqp_obj_type) {
 	case VQP_OBJ_IP_ADDRESS:
+            if (vqp_obj_len != 4)
+                goto trunc;
             ND_PRINT((ndo, "%s (0x%08x)", ipaddr_string(ndo, tptr), EXTRACT_32BITS(tptr)));
             break;
             /* those objects have similar semantics - fall through */
@@ -182,6 +192,8 @@
             /* those objects have similar semantics - fall through */
 	case VQP_OBJ_MAC_ADDRESS:
 	case VQP_OBJ_MAC_NULL:
+            if (vqp_obj_len != ETHER_ADDR_LEN)
+                goto trunc;
 	      ND_PRINT((ndo, "%s", etheraddr_string(ndo, tptr)));
               break;
         default:
```
