# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in c
**Pair ID:** 1213_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1213_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```c
Lines 4786-4826 of the vulnerable file.

            ssn->server.tcp_flags != 0)
        {
            SCLogDebug("ssn %p: removing ASYNC flag as we have packets on both sides", ssn);
            ssn->flags &= ~STREAMTCP_FLAG_ASYNC;
        }
    }

    /* update counters */
    if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        StatsIncr(tv, stt->counter_tcp_synack);
    } else if (p->tcph->th_flags & (TH_SYN)) {
        StatsIncr(tv, stt->counter_tcp_syn);
    }
    if (p->tcph->th_flags & (TH_RST)) {
        StatsIncr(tv, stt->counter_tcp_rst);
    }

    /* broken TCP http://ask.wireshark.org/questions/3183/acknowledgment-number-broken-tcp-the-acknowledge-field-is-nonzero-while-the-ack-flag-is-not-set */
    if (!(p->tcph->th_flags & TH_ACK) && TCP_GET_ACK(p) != 0) {
        StreamTcpSetEvent(p, STREAM_PKT_BROKEN_ACK);
    }

    /* If we are on IPS mode, and got a drop action triggered from
     * the IP only module, or from a reassembled msg and/or from an
     * applayer detection, then drop the rest of the packets of the
     * same stream and avoid inspecting it any further */
    if (StreamTcpCheckFlowDrops(p) == 1) {
        SCLogDebug("This flow/stream triggered a drop rule");
        FlowSetNoPacketInspectionFlag(p->flow);
        DecodeSetNoPacketInspectionFlag(p);
        StreamTcpDisableAppLayer(p->flow);
        PACKET_DROP(p);
        /* return the segments to the pool */
        StreamTcpSessionPktFree(p);
        SCReturnInt(0);
    }

    if (ssn == NULL || ssn->state == TCP_NONE) {
        if (StreamTcpPacketStateNone(tv, p, stt, ssn, &stt->pseudo_queue) == -1) {
            goto error;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4803,6 +4803,7 @@
     /* broken TCP http://ask.wireshark.org/questions/3183/acknowledgment-number-broken-tcp-the-acknowledge-field-is-nonzero-while-the-ack-flag-is-not-set */
     if (!(p->tcph->th_flags & TH_ACK) && TCP_GET_ACK(p) != 0) {
         StreamTcpSetEvent(p, STREAM_PKT_BROKEN_ACK);
+        goto error;
     }
 
     /* If we are on IPS mode, and got a drop action triggered from
@@ -6929,7 +6930,7 @@
 
     tcph.th_win = htons(5480);
     tcph.th_seq = htonl(10);
-    tcph.th_ack = htonl(11);
+    tcph.th_ack = 0;
     tcph.th_flags = TH_SYN;
     p->tcph = &tcph;
 
```
