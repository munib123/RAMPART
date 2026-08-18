# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 721_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `721_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 79-119 of the vulnerable file.

            /* origin indication: compatible with tunnel */
            case 0x0:
                /* offset is coherent with len and presence of an IPv6 header */
                if (len >= TEREDO_ORIG_INDICATION_LENGTH + IPV6_HEADER_LEN)
                    start += TEREDO_ORIG_INDICATION_LENGTH;
                else
                    return TM_ECODE_FAILED;
                break;
            /* authentication: negotiation not real tunnel */
            case 0x1:
                return TM_ECODE_FAILED;
            /* this case is not possible in Teredo: not that protocol */
            default:
                return TM_ECODE_FAILED;
        }
    }

    /* There is no specific field that we can check to prove that the packet
     * is a Teredo packet. We've zapped here all the possible Teredo header
     * and we should have an IPv6 packet at the start pointer.
     * We then can only do two checks before sending the encapsulated packets
     * to decoding:
     *  - The packet has a protocol version which is IPv6.
     *  - The IPv6 length of the packet matches what remains in buffer.
     */
    if (IP_GET_RAW_VER(start) == 6) {
        IPV6Hdr *thdr = (IPV6Hdr *)start;
        if (len ==  IPV6_HEADER_LEN +
                IPV6_GET_RAW_PLEN(thdr) + (start - pkt)) {
            if (pq != NULL) {
                int blen = len - (start - pkt);
                /* spawn off tunnel packet */
                Packet *tp = PacketTunnelPktSetup(tv, dtv, p, start, blen,
                                                  DECODE_TUNNEL_IPV6, pq);
                if (tp != NULL) {
                    PKT_SET_SRC(tp, PKT_SRC_DECODER_TEREDO);
                    /* add the tp to the packet queue. */
                    PacketEnqueue(pq,tp);
                    StatsIncr(tv, dtv->counter_teredo);
                    return TM_ECODE_OK;
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,20 +96,34 @@
     /* There is no specific field that we can check to prove that the packet
      * is a Teredo packet. We've zapped here all the possible Teredo header
      * and we should have an IPv6 packet at the start pointer.
-     * We then can only do two checks before sending the encapsulated packets
+     * We then can only do a few checks before sending the encapsulated packets
      * to decoding:
      *  - The packet has a protocol version which is IPv6.
      *  - The IPv6 length of the packet matches what remains in buffer.
+     *  - HLIM is 0. This would technically be valid, but still weird.
+     *  - NH 0 (HOP) and not enough data.
+     *
+     *  If all these conditions are met, the tunnel decoder will be called.
+     *  If the packet gets an invalid event set, it will still be rejected.
      */
     if (IP_GET_RAW_VER(start) == 6) {
         IPV6Hdr *thdr = (IPV6Hdr *)start;
+
+        /* ignore hoplimit 0 packets, most likely an artifact of bad detection */
+        if (IPV6_GET_RAW_HLIM(thdr) == 0)
+            return TM_ECODE_FAILED;
+
+        /* if nh is 0 (HOP) with little data we have a bogus packet */
+        if (IPV6_GET_RAW_NH(thdr) == 0 && IPV6_GET_RAW_PLEN(thdr) < 8)
+            return TM_ECODE_FAILED;
+
         if (len ==  IPV6_HEADER_LEN +
                 IPV6_GET_RAW_PLEN(thdr) + (start - pkt)) {
             if (pq != NULL) {
                 int blen = len - (start - pkt);
                 /* spawn off tunnel packet */
                 Packet *tp = PacketTunnelPktSetup(tv, dtv, p, start, blen,
-                                                  DECODE_TUNNEL_IPV6, pq);
+                                                  DECODE_TUNNEL_IPV6_TEREDO, pq);
                 if (tp != NULL) {
                     PKT_SET_SRC(tp, PKT_SRC_DECODER_TEREDO);
                     /* add the tp to the packet queue. */
```
