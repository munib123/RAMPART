# CrossVul Fix Pair: Improper Neutralization in c
**Pair ID:** 3936_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-707
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3936_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization - If a message is malformed, it may cause the message to be incorrectly interpreted.

## Vulnerable Code
```c
Lines 441-481 of the vulnerable file.


  (*session_ptr)->pending_local_max_concurrent_stream =
      NGHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS;
  (*session_ptr)->pending_enable_push = 1;

  if (server) {
    (*session_ptr)->server = 1;
  }

  init_settings(&(*session_ptr)->remote_settings);
  init_settings(&(*session_ptr)->local_settings);

  (*session_ptr)->max_incoming_reserved_streams =
      NGHTTP2_MAX_INCOMING_RESERVED_STREAMS;

  /* Limit max outgoing concurrent streams to sensible value */
  (*session_ptr)->remote_settings.max_concurrent_streams = 100;

  (*session_ptr)->max_send_header_block_length = NGHTTP2_MAX_HEADERSLEN;
  (*session_ptr)->max_outbound_ack = NGHTTP2_DEFAULT_MAX_OBQ_FLOOD_ITEM;

  if (option) {
    if ((option->opt_set_mask & NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE) &&
        option->no_auto_window_update) {

      (*session_ptr)->opt_flags |= NGHTTP2_OPTMASK_NO_AUTO_WINDOW_UPDATE;
    }

    if (option->opt_set_mask & NGHTTP2_OPT_PEER_MAX_CONCURRENT_STREAMS) {

      (*session_ptr)->remote_settings.max_concurrent_streams =
          option->peer_max_concurrent_streams;
    }

    if (option->opt_set_mask & NGHTTP2_OPT_MAX_RESERVED_REMOTE_STREAMS) {

      (*session_ptr)->max_incoming_reserved_streams =
          option->max_reserved_remote_streams;
    }

    if ((option->opt_set_mask & NGHTTP2_OPT_NO_RECV_CLIENT_MAGIC) &&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -458,6 +458,7 @@
 
   (*session_ptr)->max_send_header_block_length = NGHTTP2_MAX_HEADERSLEN;
   (*session_ptr)->max_outbound_ack = NGHTTP2_DEFAULT_MAX_OBQ_FLOOD_ITEM;
+  (*session_ptr)->max_settings = NGHTTP2_DEFAULT_MAX_SETTINGS;
 
   if (option) {
     if ((option->opt_set_mask & NGHTTP2_OPT_NO_AUTO_WINDOW_UPDATE) &&
@@ -520,6 +521,11 @@
 
     if (option->opt_set_mask & NGHTTP2_OPT_MAX_OUTBOUND_ACK) {
       (*session_ptr)->max_outbound_ack = option->max_outbound_ack;
+    }
+
+    if ((option->opt_set_mask & NGHTTP2_OPT_MAX_SETTINGS) &&
+        option->max_settings) {
+      (*session_ptr)->max_settings = option->max_settings;
     }
   }
 
@@ -5657,6 +5663,16 @@
           iframe->max_niv =
               iframe->frame.hd.length / NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH + 1;
 
+          if (iframe->max_niv - 1 > session->max_settings) {
+            rv = nghttp2_session_terminate_session_with_reason(
+                session, NGHTTP2_ENHANCE_YOUR_CALM,
+                "SETTINGS: too many setting entries");
+            if (nghttp2_is_fatal(rv)) {
+              return rv;
+            }
+            return (ssize_t)inlen;
+          }
+
           iframe->iv = nghttp2_mem_malloc(mem, sizeof(nghttp2_settings_entry) *
                                                    iframe->max_niv);
 
@@ -7425,6 +7441,11 @@
   if (settings_payloadlen % NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH) {
     return NGHTTP2_ERR_INVALID_ARGUMENT;
   }
+  /* SETTINGS frame contains too many settings */
+  if (settings_payloadlen / NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH
+        > session->max_settings) {
+    return NGHTTP2_ERR_TOO_MANY_SETTINGS;
+  }
   rv = nghttp2_frame_unpack_settings_payload2(&iv, &niv, settings_payload,
                                               settings_payloadlen, mem);
   if (rv != 0) {
```
