# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1209_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1209_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 19-63 of the vulnerable file.


#include "keepkey/board/usb.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/variant.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/util.h"

#include <nanopb.h>

#include <assert.h>
#include <string.h>

static const MessagesMap_t *MessagesMap = NULL;
static size_t map_size = 0;
static msg_failure_t msg_failure;

#if DEBUG_LINK
static msg_debug_link_get_state_t msg_debug_link_get_state;
#endif

/* Tiny messages */
static bool msg_tiny_flag = false;
static CONFIDENTIAL uint8_t msg_tiny[MSG_TINY_BFR_SZ];
static uint16_t msg_tiny_id = MSG_TINY_TYPE_ERROR; /* Default to error type */

/* Allow mapped messages to reset message stack.  This variable by itself doesn't
 * do much but messages down the line can use it to determine for to gracefully
 * exit from a message should the message stack been reset
 */
bool reset_msg_stack = false;

/*
 * message_map_entry() - Finds a requested message map entry
 *
 * INPUT
 *     - type: type of message (normal or debug)
 *     - msg_id: message id
 *     - dir: direction of message
 * OUTPUT
 *     entry if found
 */
static const MessagesMap_t *message_map_entry(MessageMapType type,
        MessageType msg_id,
        MessageMapDirection dir)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,11 +37,6 @@
 static msg_debug_link_get_state_t msg_debug_link_get_state;
 #endif
 
-/* Tiny messages */
-static bool msg_tiny_flag = false;
-static CONFIDENTIAL uint8_t msg_tiny[MSG_TINY_BFR_SZ];
-static uint16_t msg_tiny_id = MSG_TINY_TYPE_ERROR; /* Default to error type */
-
 /* Allow mapped messages to reset message stack.  This variable by itself doesn't
  * do much but messages down the line can use it to determine for to gracefully
  * exit from a message should the message stack been reset
@@ -145,28 +140,6 @@
     }
 
     entry->process_func(decode_buffer);
-}
-
-/*
- * tiny_dispatch() - Process received tiny messages
- *
- * INPUT
- *     - entry: pointer to message entry
- *     - msg: pointer to received message buffer
- *     - msg_size: size of message
- * OUTPUT
- *     none
- *
- */
-static void tiny_dispatch(const MessagesMap_t *entry, uint8_t *msg, uint32_t msg_size)
-{
-    if (!pb_parse(entry, msg, msg_size, msg_tiny)) {
-        call_msg_failure_handler(FailureType_Failure_UnexpectedMessage,
-                                 "Could not parse tiny protocol buffer message");
-        return;
-    }
-
-    msg_tiny_id = entry->msg_id;
 }
 
 /*
@@ -337,31 +310,93 @@
     entry = NULL;
 }
 
+/* Tiny messages */
+static bool msg_tiny_flag = false;
+static CONFIDENTIAL uint8_t msg_tiny[MSG_TINY_BFR_SZ];
+static uint16_t msg_tiny_id = MSG_TINY_TYPE_ERROR; /* Default to error type */
+
+_Static_assert(sizeof(msg_tiny) >= sizeof(Cancel), "msg_tiny too tiny");
+_Static_assert(sizeof(msg_tiny) >= sizeof(Initialize), "msg_tiny too tiny");
+_Static_assert(sizeof(msg_tiny) >= sizeof(PassphraseAck), "msg_tiny too tiny");
+_Static_assert(sizeof(msg_tiny) >= sizeof(ButtonAck), "msg_tiny too tiny");
+_Static_assert(sizeof(msg_tiny) >= sizeof(PinMatrixAck), "msg_tiny too tiny");
+#if DEBUG_LINK
+_Static_assert(sizeof(msg_tiny) >= sizeof(DebugLinkDecision),
+               "msg_tiny too tiny");
+_Static_assert(sizeof(msg_tiny) >= sizeof(DebugLinkGetState),
+               "msg_tiny too tiny");
+#endif
+
+static void msg_read_tiny(const uint8_t *msg, size_t len) {
+    if (len != 64)
+        return;
+
+    uint8_t buf[64];
+    memcpy(buf, msg, sizeof(buf));
+
+    if (buf[0] != '?' || buf[1] != '#' || buf[2] != '#') {
+        (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Malformed tiny packet");
+        return;
+    }
+
+    uint16_t msgId = buf[4] | ((uint16_t)buf[3]) << 8;
+    uint32_t msgSize = buf[8]        |
+            ((uint32_t)buf[7]) <<  8 |
+            ((uint32_t)buf[6]) << 16 |
+            ((uint32_t)buf[5]) << 24;
+
+    if (msgSize > 64 - 9) {
+        (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Malformed tiny packet");
+        return;
+    }
+
+    const pb_field_t *fields = NULL;
+    pb_istream_t stream = pb_istream_from_buffer(buf + 9, msgSize);
+
+    switch (msgId) {
+    case MessageType_MessageType_PinMatrixAck:
+        fields = PinMatrixAck_fields;
+        break;
+    case MessageType_MessageType_ButtonAck:
+        fields = ButtonAck_fields;
+        break;
+    case MessageType_MessageType_PassphraseAck:
+        fields = PassphraseAck_fields;
+        break;
+    case MessageType_MessageType_Cancel:
+        fields = Cancel_fields;
+        break;
+    case MessageType_MessageType_Initialize:
+        fields = Initialize_fields;
+        break;
+#if DEBUG_LINK
+    case MessageType_MessageType_DebugLinkDecision:
+        fields = DebugLinkDecision_fields;
+        break;
+    case MessageType_MessageType_DebugLinkGetState:
+        fields = DebugLinkGetState_fields;
+        break;
+#endif
+    }
+
+    if (fields) {
+        bool status = pb_decode(&stream, fields, msg_tiny);
+        if (status) {
+            msg_tiny_id = msgId;
+        } else {
+            (*msg_failure)(FailureType_Failure_SyntaxError, stream.errmsg);
+            msg_tiny_id = 0xffff;
+        }
+    } else {
+        (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unknown message");
+        msg_tiny_id = 0xffff;
+    }
+}
+
 void handle_usb_rx(const void *msg, size_t len)
 {
     if (msg_tiny_flag) {
-        uint8_t buf[64];
-        memcpy(buf, msg, sizeof(buf));
-
-        uint16_t msgId = buf[4] | ((uint16_t)buf[3]) << 8;
-        uint32_t msgSize = buf[8]        |
-                ((uint32_t)buf[7]) <<  8 |
-                ((uint32_t)buf[6]) << 16 |
-                ((uint32_t)buf[5]) << 24;
-
-        if (msgSize > 64 - 9) {
-            (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Malformed tiny packet");
-            return;
-        }
-
-        // Determine callback handler and message map type.
-        const MessagesMap_t *entry = message_map_entry(NORMAL_MSG, msgId, IN_MSG);
-        if (!entry) {
-            (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unknown message");
-            return;
-        }
-
-        tiny_dispatch(entry, buf + 9, msgSize);
+        msg_read_tiny(msg, len);
     } else {
         usb_rx_helper(msg, len, NORMAL_MSG);
     }
@@ -371,28 +406,7 @@
 void handle_debug_usb_rx(const void *msg, size_t len)
 {
     if (msg_tiny_flag) {
-        uint8_t buf[64];
-        memcpy(buf, msg, sizeof(buf));
-
-        uint16_t msgId = buf[4] | ((uint16_t)buf[3]) << 8;
-        uint32_t msgSize = buf[8]        |
-                ((uint32_t)buf[7]) <<  8 |
-                ((uint32_t)buf[6]) << 16 |
-                ((uint32_t)buf[5]) << 24;
-
-        if (msgSize > 64 - 9) {
-            (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Malformed tiny packet");
-            return;
-        }
-
-        // Determine callback handler and message map type.
-        const MessagesMap_t *entry = message_map_entry(DEBUG_MSG, msgId, IN_MSG);
-        if (!entry) {
-            (*msg_failure)(FailureType_Failure_UnexpectedMessage, "Unknown message");
-            return;
-        }
-
-        tiny_dispatch(entry, buf + 9, msgSize);
+        msg_read_tiny(msg, len);
     } else {
         usb_rx_helper(msg, len, DEBUG_MSG);
     }
```
