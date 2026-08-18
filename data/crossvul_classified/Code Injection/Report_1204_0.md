# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 1204_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1204_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 1346-1386 of the vulnerable file.

    SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 "", ssn,
            ssn->server.next_win);
    SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 "", ssn,
            ssn->client.next_win);
    SCLogDebug("ssn %p: ssn->server.isn %" PRIu32 ", "
            "ssn->server.next_seq %" PRIu32 ", "
            "ssn->server.last_ack %" PRIu32 " "
            "(ssn->client.last_ack %" PRIu32 ")", ssn,
            ssn->server.isn, ssn->server.next_seq,
            ssn->server.last_ack, ssn->client.last_ack);

    /* unset the 4WHS flag as we received this SYN/ACK as part of a
     * (so far) valid 3WHS */
    if (ssn->flags & STREAMTCP_FLAG_4WHS)
        SCLogDebug("ssn %p: STREAMTCP_FLAG_4WHS unset, normal SYN/ACK"
                " so considering 3WHS", ssn);

    ssn->flags &=~ STREAMTCP_FLAG_4WHS;
}

/**
 *  \brief  Function to handle the TCP_SYN_SENT state. The function handles
 *          SYN, SYN/ACK, RST packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateSynSent(ThreadVars *tv, Packet *p,
                        StreamTcpThread *stt, TcpSession *ssn, PacketQueue *pq)
{
    if (ssn == NULL)
        return -1;

    SCLogDebug("ssn %p: pkt received: %s", ssn, PKT_IS_TOCLIENT(p) ?
               "toclient":"toserver");

    /* RST */
    if (p->tcph->th_flags & TH_RST) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1363,6 +1363,39 @@
     ssn->flags &=~ STREAMTCP_FLAG_4WHS;
 }
 
+/** \internal
+ *  \brief detect timestamp anomalies when processing responses to the
+ *         SYN packet.
+ *  \retval true packet is ok
+ *  \retval false packet is bad
+ */
+static inline bool StateSynSentValidateTimestamp(TcpSession *ssn, Packet *p)
+{
+    /* we only care about evil server here, so skip TS packets */
+    if (PKT_IS_TOSERVER(p) || !(TCP_HAS_TS(p))) {
+        return true;
+    }
+
+    TcpStream *receiver_stream = &ssn->client;
+    uint32_t ts_echo = TCP_GET_TSECR(p);
+    if ((receiver_stream->flags & STREAMTCP_STREAM_FLAG_TIMESTAMP) != 0) {
+        if (receiver_stream->last_ts != 0 && ts_echo != 0 &&
+            ts_echo != receiver_stream->last_ts)
+        {
+            SCLogDebug("ssn %p: BAD TSECR echo %u recv %u", ssn,
+                    ts_echo, receiver_stream->last_ts);
+            return false;
+        }
+    } else {
+        if (receiver_stream->last_ts == 0 && ts_echo != 0) {
+            SCLogDebug("ssn %p: BAD TSECR echo %u recv %u", ssn,
+                    ts_echo, receiver_stream->last_ts);
+            return false;
+        }
+    }
+    return true;
+}
+
 /**
  *  \brief  Function to handle the TCP_SYN_SENT state. The function handles
  *          SYN, SYN/ACK, RST packets and correspondingly changes the connection
@@ -1381,6 +1414,10 @@
 
     SCLogDebug("ssn %p: pkt received: %s", ssn, PKT_IS_TOCLIENT(p) ?
                "toclient":"toserver");
+
+    /* check for bad responses */
+    if (StateSynSentValidateTimestamp(ssn, p) == false)
+        return -1;
 
     /* RST */
     if (p->tcph->th_flags & TH_RST) {
```
