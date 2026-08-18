# CrossVul Fix Pair: Improper Neutralization in c
**Pair ID:** 3937_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-707
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3937_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization - If a message is malformed, it may cause the message to be incorrectly interpreted.

## Vulnerable Code
```c
Lines 5636-5676 of the vulnerable file.

        }

        iframe->state = NGHTTP2_IB_READ_NBYTE;

        inbound_frame_set_mark(iframe, 4);

        break;
      case NGHTTP2_SETTINGS:
        DEBUGF("recv: SETTINGS\n");

        iframe->frame.hd.flags &= NGHTTP2_FLAG_ACK;

        if ((iframe->frame.hd.length % NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH) ||
            ((iframe->frame.hd.flags & NGHTTP2_FLAG_ACK) &&
             iframe->payloadleft > 0)) {
          busy = 1;
          iframe->state = NGHTTP2_IB_FRAME_SIZE_ERROR;
          break;
        }

        iframe->state = NGHTTP2_IB_READ_SETTINGS;

        if (iframe->payloadleft) {
          nghttp2_settings_entry *min_header_table_size_entry;

          /* We allocate iv with additional one entry, to store the
             minimum header table size. */
          iframe->max_niv =
              iframe->frame.hd.length / NGHTTP2_FRAME_SETTINGS_ENTRY_LENGTH + 1;

          if (iframe->max_niv - 1 > session->max_settings) {
            rv = nghttp2_session_terminate_session_with_reason(
                session, NGHTTP2_ENHANCE_YOUR_CALM,
                "SETTINGS: too many setting entries");
            if (nghttp2_is_fatal(rv)) {
              return rv;
            }
            return (ssize_t)inlen;
          }

          iframe->iv = nghttp2_mem_malloc(mem, sizeof(nghttp2_settings_entry) *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5653,6 +5653,12 @@
           break;
         }
 
+        /* Check the settings flood counter early to be safe */
+        if (session->obq_flood_counter_ >= session->max_outbound_ack &&
+            !(iframe->frame.hd.flags & NGHTTP2_FLAG_ACK)) {
+          return NGHTTP2_ERR_FLOODED;
+        }
+
         iframe->state = NGHTTP2_IB_READ_SETTINGS;
 
         if (iframe->payloadleft) {
```
