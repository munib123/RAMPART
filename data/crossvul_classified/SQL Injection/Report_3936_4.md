# CrossVul Fix Pair: Improper Neutralization in c
**Pair ID:** 3936_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-707
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3936_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization - If a message is malformed, it may cause the message to be incorrectly interpreted.

## Vulnerable Code
```c
Lines 104-123 of the vulnerable file.

                                                     size_t val) {
  option->opt_set_mask |= NGHTTP2_OPT_MAX_SEND_HEADER_BLOCK_LENGTH;
  option->max_send_header_block_length = val;
}

void nghttp2_option_set_max_deflate_dynamic_table_size(nghttp2_option *option,
                                                       size_t val) {
  option->opt_set_mask |= NGHTTP2_OPT_MAX_DEFLATE_DYNAMIC_TABLE_SIZE;
  option->max_deflate_dynamic_table_size = val;
}

void nghttp2_option_set_no_closed_streams(nghttp2_option *option, int val) {
  option->opt_set_mask |= NGHTTP2_OPT_NO_CLOSED_STREAMS;
  option->no_closed_streams = val;
}

void nghttp2_option_set_max_outbound_ack(nghttp2_option *option, size_t val) {
  option->opt_set_mask |= NGHTTP2_OPT_MAX_OUTBOUND_ACK;
  option->max_outbound_ack = val;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,3 +121,8 @@
   option->opt_set_mask |= NGHTTP2_OPT_MAX_OUTBOUND_ACK;
   option->max_outbound_ack = val;
 }
+
+void nghttp2_option_set_max_settings(nghttp2_option *option, size_t val) {
+  option->opt_set_mask |= NGHTTP2_OPT_MAX_SETTINGS;
+  option->max_settings = val;
+}
```
