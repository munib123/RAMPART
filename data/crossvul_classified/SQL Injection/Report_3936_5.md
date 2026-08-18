# CrossVul Fix Pair: Improper Neutralization in c
**Pair ID:** 3936_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-707
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3936_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization - If a message is malformed, it may cause the message to be incorrectly interpreted.

## Vulnerable Code
```c
Lines 50-90 of the vulnerable file.

   * SETTINGS_MAX_CONCURRENT_STREAMS in SETTINGS frame from remote
   * endpoint, SETTINGS_MAX_CONCURRENT_STREAMS is unlimited. This may
   * cause problem if local endpoint submits lots of requests
   * initially and sending them at once to the remote peer may lead to
   * the rejection of some requests. Specifying this option to the
   * sensible value, say 100, may avoid this kind of issue. This value
   * will be overwritten if the local endpoint receives
   * SETTINGS_MAX_CONCURRENT_STREAMS from the remote endpoint.
   */
  NGHTTP2_OPT_PEER_MAX_CONCURRENT_STREAMS = 1 << 1,
  NGHTTP2_OPT_NO_RECV_CLIENT_MAGIC = 1 << 2,
  NGHTTP2_OPT_NO_HTTP_MESSAGING = 1 << 3,
  NGHTTP2_OPT_MAX_RESERVED_REMOTE_STREAMS = 1 << 4,
  NGHTTP2_OPT_USER_RECV_EXT_TYPES = 1 << 5,
  NGHTTP2_OPT_NO_AUTO_PING_ACK = 1 << 6,
  NGHTTP2_OPT_BUILTIN_RECV_EXT_TYPES = 1 << 7,
  NGHTTP2_OPT_MAX_SEND_HEADER_BLOCK_LENGTH = 1 << 8,
  NGHTTP2_OPT_MAX_DEFLATE_DYNAMIC_TABLE_SIZE = 1 << 9,
  NGHTTP2_OPT_NO_CLOSED_STREAMS = 1 << 10,
  NGHTTP2_OPT_MAX_OUTBOUND_ACK = 1 << 11,
} nghttp2_option_flag;

/**
 * Struct to store option values for nghttp2_session.
 */
struct nghttp2_option {
  /**
   * NGHTTP2_OPT_MAX_SEND_HEADER_BLOCK_LENGTH
   */
  size_t max_send_header_block_length;
  /**
   * NGHTTP2_OPT_MAX_DEFLATE_DYNAMIC_TABLE_SIZE
   */
  size_t max_deflate_dynamic_table_size;
  /**
   * NGHTTP2_OPT_MAX_OUTBOUND_ACK
   */
  size_t max_outbound_ack;
  /**
   * Bitwise OR of nghttp2_option_flag to determine that which fields
   * are specified.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,6 +67,7 @@
   NGHTTP2_OPT_MAX_DEFLATE_DYNAMIC_TABLE_SIZE = 1 << 9,
   NGHTTP2_OPT_NO_CLOSED_STREAMS = 1 << 10,
   NGHTTP2_OPT_MAX_OUTBOUND_ACK = 1 << 11,
+  NGHTTP2_OPT_MAX_SETTINGS = 1 << 12,
 } nghttp2_option_flag;
 
 /**
@@ -85,6 +86,10 @@
    * NGHTTP2_OPT_MAX_OUTBOUND_ACK
    */
   size_t max_outbound_ack;
+  /**
+   * NGHTTP2_OPT_MAX_SETTINGS
+   */
+  size_t max_settings;
   /**
    * Bitwise OR of nghttp2_option_flag to determine that which fields
    * are specified.
```
