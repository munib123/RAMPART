# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1175_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1175_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 402-443 of the vulnerable file.

    return 0;
}

/*
 * _libssh2_packet_add
 *
 * Create a new packet and attach it to the brigade. Called from the transport
 * layer when it has received a packet.
 *
 * The input pointer 'data' is pointing to allocated data that this function
 * is asked to deal with so on failure OR success, it must be freed fine.
 * The only exception is when the return code is LIBSSH2_ERROR_EAGAIN.
 *
 * This function will always be called with 'datalen' greater than zero.
 */
int
_libssh2_packet_add(LIBSSH2_SESSION * session, unsigned char *data,
                    size_t datalen, int macstate)
{
    int rc = 0;
    char *message = NULL;
    char *language = NULL;
    size_t message_len = 0;
    size_t language_len = 0;
    LIBSSH2_CHANNEL *channelp = NULL;
    size_t data_head = 0;
    unsigned char msg = data[0];

    switch(session->packAdd_state) {
    case libssh2_NB_state_idle:
        _libssh2_debug(session, LIBSSH2_TRACE_TRANS,
                       "Packet type %d received, length=%d",
                       (int) msg, (int) datalen);

        if((macstate == LIBSSH2_MAC_INVALID) &&
            (!session->macerror ||
             LIBSSH2_MACERROR(session, (char *) data, datalen))) {
            /* Bad MAC input, but no callback set or non-zero return from the
               callback */

            LIBSSH2_FREE(session, data);
            return _libssh2_error(session, LIBSSH2_ERROR_INVALID_MAC,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -419,8 +419,8 @@
                     size_t datalen, int macstate)
 {
     int rc = 0;
-    char *message = NULL;
-    char *language = NULL;
+    unsigned char *message = NULL;
+    unsigned char *language = NULL;
     size_t message_len = 0;
     size_t language_len = 0;
     LIBSSH2_CHANNEL *channelp = NULL;
@@ -472,33 +472,23 @@
 
         case SSH_MSG_DISCONNECT:
             if(datalen >= 5) {
-                size_t reason = _libssh2_ntohu32(data + 1);
-
-                if(datalen >= 9) {
-                    message_len = _libssh2_ntohu32(data + 5);
-
-                    if(message_len < datalen-13) {
-                        /* 9 = packet_type(1) + reason(4) + message_len(4) */
-                        message = (char *) data + 9;
-
-                        language_len =
-                            _libssh2_ntohu32(data + 9 + message_len);
-                        language = (char *) data + 9 + message_len + 4;
-
-                        if(language_len > (datalen-13-message_len)) {
-                            /* bad input, clear info */
-                            language = message = NULL;
-                            language_len = message_len = 0;
-                        }
-                    }
-                    else
-                        /* bad size, clear it */
-                        message_len = 0;
+                uint32_t reason = 0;
+                struct string_buf buf;
+                buf.data = (unsigned char *)data;
+                buf.dataptr = buf.data;
+                buf.len = datalen;
+                buf.dataptr++; /* advance past type */
+
+                _libssh2_get_u32(&buf, &reason);
+                _libssh2_get_string(&buf, &message, &message_len);
+                _libssh2_get_string(&buf, &language, &language_len);
+
+                if(session->ssh_msg_disconnect) {
+                    LIBSSH2_DISCONNECT(session, reason, (const char *)message,
+                                       message_len, (const char *)language,
+                                       language_len);
                 }
-                if(session->ssh_msg_disconnect) {
-                    LIBSSH2_DISCONNECT(session, reason, message,
-                                       message_len, language, language_len);
-                }
+
                 _libssh2_debug(session, LIBSSH2_TRACE_TRANS,
                                "Disconnect(%d): %s(%s)", reason,
                                message, language);
```
