# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 721_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `721_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 62-102 of the vulnerable file.

#include "tmqh-packetpool.h"
#include "util-profiling.h"
#include "pkt-var.h"
#include "util-mpm-ac.h"

#include "output.h"
#include "output-flow.h"

extern bool stats_decoder_events;
extern bool stats_stream_events;

int DecodeTunnel(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        uint8_t *pkt, uint32_t len, PacketQueue *pq, enum DecodeTunnelProto proto)
{
    switch (proto) {
        case DECODE_TUNNEL_PPP:
            return DecodePPP(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_IPV4:
            return DecodeIPV4(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_IPV6:
            return DecodeIPV6(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_VLAN:
            return DecodeVLAN(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_ETHERNET:
            return DecodeEthernet(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_ERSPAN:
            return DecodeERSPAN(tv, dtv, p, pkt, len, pq);
        default:
            SCLogInfo("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.", proto);
            break;
    }
    return TM_ECODE_OK;
}

/**
 * \brief Return a malloced packet.
 */
void PacketFree(Packet *p)
{
    PACKET_DESTRUCTOR(p);
    SCFree(p);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,6 +79,7 @@
         case DECODE_TUNNEL_IPV4:
             return DecodeIPV4(tv, dtv, p, pkt, len, pq);
         case DECODE_TUNNEL_IPV6:
+        case DECODE_TUNNEL_IPV6_TEREDO:
             return DecodeIPV6(tv, dtv, p, pkt, len, pq);
         case DECODE_TUNNEL_VLAN:
             return DecodeVLAN(tv, dtv, p, pkt, len, pq);
@@ -87,7 +88,7 @@
         case DECODE_TUNNEL_ERSPAN:
             return DecodeERSPAN(tv, dtv, p, pkt, len, pq);
         default:
-            SCLogInfo("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.", proto);
+            SCLogDebug("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.", proto);
             break;
     }
     return TM_ECODE_OK;
@@ -303,8 +304,12 @@
     ret = DecodeTunnel(tv, dtv, p, GET_PKT_DATA(p),
                        GET_PKT_LEN(p), pq, proto);
 
-    if (unlikely(ret != TM_ECODE_OK)) {
-        /* Not a tunnel packet, just a pseudo packet */
+    if (unlikely(ret != TM_ECODE_OK) ||
+            (proto == DECODE_TUNNEL_IPV6_TEREDO && (p->flags & PKT_IS_INVALID)))
+    {
+        /* Not a (valid) tunnel packet */
+        SCLogDebug("tunnel packet is invalid");
+
         p->root = NULL;
         UNSET_TUNNEL_PKT(p);
         TmqhOutputPacketpool(tv, p);
```
