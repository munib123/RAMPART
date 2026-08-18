# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 721_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `721_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 133-173 of the vulnerable file.

    p->ip6eh.fh_header_offset = frag_hdr_offset;
    p->ip6eh.fh_data_offset = data_offset;
    p->ip6eh.fh_data_len = data_len;

    /* if we have a prev hdr, store the type and offset of it */
    if (prev_hdrextlen) {
        p->ip6eh.fh_prev_hdr_offset = frag_hdr_offset - prev_hdrextlen;
    }

    SCLogDebug("IPV6 FH: frag_hdr_offset %u, data_offset %u, data_len %u",
            p->ip6eh.fh_header_offset, p->ip6eh.fh_data_offset,
            p->ip6eh.fh_data_len);
}

static void
DecodeIPV6ExtHdrs(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCEnter();

    uint8_t *orig_pkt = pkt;
    uint8_t nh = 0; /* careful, 0 is actually a real type */
    uint16_t hdrextlen = 0;
    uint16_t plen;
    char dstopts = 0;
    char exthdr_fh_done = 0;
    int hh = 0;
    int rh = 0;
    int eh = 0;
    int ah = 0;

    nh = IPV6_GET_NH(p);
    plen = len;

    while(1)
    {
        /* No upper layer, but we do have data. Suspicious. */
        if (nh == IPPROTO_NONE && plen > 0) {
            ENGINE_SET_EVENT(p, IPV6_DATA_AFTER_NONE_HEADER);
            SCReturn;
        }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,9 +150,9 @@
     SCEnter();
 
     uint8_t *orig_pkt = pkt;
-    uint8_t nh = 0; /* careful, 0 is actually a real type */
+    uint8_t nh = IPV6_GET_NH(p); /* careful, 0 is actually a real type */
     uint16_t hdrextlen = 0;
-    uint16_t plen;
+    uint16_t plen = len;
     char dstopts = 0;
     char exthdr_fh_done = 0;
     int hh = 0;
@@ -160,18 +160,18 @@
     int eh = 0;
     int ah = 0;
 
-    nh = IPV6_GET_NH(p);
-    plen = len;
-
     while(1)
     {
-        /* No upper layer, but we do have data. Suspicious. */
-        if (nh == IPPROTO_NONE && plen > 0) {
-            ENGINE_SET_EVENT(p, IPV6_DATA_AFTER_NONE_HEADER);
+        if (nh == IPPROTO_NONE) {
+            if (plen > 0) {
+                /* No upper layer, but we do have data. Suspicious. */
+                ENGINE_SET_EVENT(p, IPV6_DATA_AFTER_NONE_HEADER);
+            }
             SCReturn;
         }
 
         if (plen < 2) { /* minimal needed in a hdr */
+            ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_EXTHDR);
             SCReturn;
         }
 
@@ -204,7 +204,7 @@
                 SCLogDebug("hdrextlen %"PRIu8, hdrextlen);
 
                 if (hdrextlen > plen) {
-                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
+                    ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_EXTHDR);
                     SCReturn;
                 }
 
@@ -243,7 +243,7 @@
                 IPV6_SET_L4PROTO(p,nh);
                 hdrextlen =  (*(pkt+1) + 1) << 3;
                 if (hdrextlen > plen) {
-                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
+                    ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_EXTHDR);
                     SCReturn;
                 }
 
@@ -288,7 +288,7 @@
                 if (optslen > plen) {
                     /* since the packet is long enough (we checked
                      * plen against hdrlen, the optlen must be malformed. */
-                    ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
+                    ENGINE_SET_INVALID_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                     /* skip past this extension so we can continue parsing the rest
                      * of the packet */
                     nh = *pkt;
@@ -311,7 +311,7 @@
                     }
 
                     if (offset + 1 >= optslen) {
-                        ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
+                        ENGINE_SET_INVALID_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                         break;
                     }
 
@@ -320,7 +320,7 @@
 
                     /* see if the optlen from the packet fits the total optslen */
                     if ((offset + 1 + ip6_optlen) > optslen) {
-                        ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
+                        ENGINE_SET_INVALID_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                         break;
                     }
 
@@ -339,7 +339,7 @@
                         ra->ip6ra_len  = ip6_optlen;
 
                         if (ip6_optlen < sizeof(ra->ip6ra_value)) {
-                            ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
+                            ENGINE_SET_INVALID_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                             break;
                         }
 
@@ -355,7 +355,7 @@
                         jumbo->ip6j_len  = ip6_optlen;
 
                         if (ip6_optlen < sizeof(jumbo->ip6j_payload_len)) {
-                            ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
+                            ENGINE_SET_INVALID_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                             break;
                         }
 
@@ -370,7 +370,7 @@
                         hao->ip6hao_len  = ip6_optlen;
 
                         if (ip6_optlen < sizeof(hao->ip6hao_hoa)) {
-                            ENGINE_SET_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
+                            ENGINE_SET_INVALID_EVENT(p, IPV6_EXTHDR_INVALID_OPTLEN);
                             break;
                         }
 
@@ -422,7 +422,7 @@
                 uint16_t prev_hdrextlen = hdrextlen;
                 hdrextlen = sizeof(IPV6FragHdr);
                 if (hdrextlen > plen) {
-                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
+                    ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_EXTHDR);
                     SCReturn;
                 }
 
@@ -468,7 +468,7 @@
                 IPV6_SET_L4PROTO(p,nh);
                 hdrextlen = sizeof(IPV6EspHdr);
                 if (hdrextlen > plen) {
-                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
+                    ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_EXTHDR);
                     SCReturn;
                 }
 
@@ -497,7 +497,7 @@
                 SCLogDebug("hdrextlen %"PRIu8, hdrextlen);
 
                 if (hdrextlen > plen) {
-                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
+                    ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_EXTHDR);
                     SCReturn;
                 }
 
@@ -538,7 +538,7 @@
             case IPPROTO_SHIM6:
                 hdrextlen = 8 + (*(pkt+1) * 8);  /* 8 bytes + length in 8 octet units */
                 if (hdrextlen > plen) {
-                    ENGINE_SET_EVENT(p, IPV6_TRUNC_EXTHDR);
+                    ENGINE_SET_INVALID_EVENT(p, IPV6_TRUNC_EXTHDR);
                     SCReturn;
                 }
                 nh = *pkt;
```
