# CrossVul Fix Pair: Improper Neutralization in c
**Pair ID:** 3936_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-707
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3936_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization - If a message is malformed, it may cause the message to be incorrectly interpreted.

## Vulnerable Code
```c
Lines 250-290 of the vulnerable file.

     closed streams can be accessed through single linked list
     |closed_stream_head|.  The current implementation only keeps
     incoming streams and session is initialized as server. */
  size_t num_closed_streams;
  /* The number of idle streams kept in |streams| hash.  The idle
     streams can be accessed through doubly linked list
     |idle_stream_head|.  The current implementation only keeps idle
     streams if session is initialized as server. */
  size_t num_idle_streams;
  /* The number of bytes allocated for nvbuf */
  size_t nvbuflen;
  /* Counter for detecting flooding in outbound queue.  If it exceeds
     max_outbound_ack, session will be closed. */
  size_t obq_flood_counter_;
  /* The maximum number of outgoing SETTINGS ACK and PING ACK in
     outbound queue. */
  size_t max_outbound_ack;
  /* The maximum length of header block to send.  Calculated by the
     same way as nghttp2_hd_deflate_bound() does. */
  size_t max_send_header_block_length;
  /* Next Stream ID. Made unsigned int to detect >= (1 << 31). */
  uint32_t next_stream_id;
  /* The last stream ID this session initiated.  For client session,
     this is the last stream ID it has sent.  For server session, it
     is the last promised stream ID sent in PUSH_PROMISE. */
  int32_t last_sent_stream_id;
  /* The largest stream ID received so far */
  int32_t last_recv_stream_id;
  /* The largest stream ID which has been processed in some way. This
     value will be used as last-stream-id when sending GOAWAY
     frame. */
  int32_t last_proc_stream_id;
  /* Counter of unique ID of PING. Wraps when it exceeds
     NGHTTP2_MAX_UNIQUE_ID */
  uint32_t next_unique_id;
  /* This is the last-stream-ID we have sent in GOAWAY */
  int32_t local_last_stream_id;
  /* This is the value in GOAWAY frame received from remote endpoint. */
  int32_t remote_last_stream_id;
  /* Current sender window size. This value is computed against the
     current initial window size of remote endpoint. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,6 +267,8 @@
   /* The maximum length of header block to send.  Calculated by the
      same way as nghttp2_hd_deflate_bound() does. */
   size_t max_send_header_block_length;
+  /* The maximum number of settings accepted per SETTINGS frame. */
+  size_t max_settings;
   /* Next Stream ID. Made unsigned int to detect >= (1 << 31). */
   uint32_t next_stream_id;
   /* The last stream ID this session initiated.  For client session,
```
