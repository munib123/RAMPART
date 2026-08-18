# CrossVul Fix Pair: Improper Neutralization in c
**Pair ID:** 3936_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-707
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3936_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization - If a message is malformed, it may cause the message to be incorrectly interpreted.

## Vulnerable Code
```c
Lines 212-252 of the vulnerable file.

 * The default header table size.
 */
#define NGHTTP2_DEFAULT_HEADER_TABLE_SIZE (1 << 12)

/**
 * @macro
 *
 * The client magic string, which is the first 24 bytes byte string of
 * client connection preface.
 */
#define NGHTTP2_CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/**
 * @macro
 *
 * The length of :macro:`NGHTTP2_CLIENT_MAGIC`.
 */
#define NGHTTP2_CLIENT_MAGIC_LEN 24

/**
 * @enum
 *
 * Error codes used in this library.  The code range is [-999, -500],
 * inclusive. The following values are defined:
 */
typedef enum {
  /**
   * Invalid argument passed.
   */
  NGHTTP2_ERR_INVALID_ARGUMENT = -501,
  /**
   * Out of buffer space.
   */
  NGHTTP2_ERR_BUFFER_ERROR = -502,
  /**
   * The specified protocol version is not supported.
   */
  NGHTTP2_ERR_UNSUPPORTED_VERSION = -503,
  /**
   * Used as a return value from :type:`nghttp2_send_callback`,
   * :type:`nghttp2_recv_callback` and
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -229,6 +229,13 @@
 #define NGHTTP2_CLIENT_MAGIC_LEN 24
 
 /**
+ * @macro
+ *
+ * The default max number of settings per SETTINGS frame
+ */
+#define NGHTTP2_DEFAULT_MAX_SETTINGS 32
+
+/**
  * @enum
  *
  * Error codes used in this library.  The code range is [-999, -500],
@@ -398,6 +405,11 @@
    * receives an other type of frame.
    */
   NGHTTP2_ERR_SETTINGS_EXPECTED = -536,
+  /**
+   * When a local endpoint receives too many settings entries
+   * in a single SETTINGS frame.
+   */
+  NGHTTP2_ERR_TOO_MANY_SETTINGS = -537,
   /**
    * The errors < :enum:`NGHTTP2_ERR_FATAL` mean that the library is
    * under unexpected condition and processing was terminated (e.g.,
@@ -2658,6 +2670,17 @@
  */
 NGHTTP2_EXTERN void nghttp2_option_set_max_outbound_ack(nghttp2_option *option,
                                                         size_t val);
+
+/**
+ * @function
+ *
+ * This function sets the maximum number of SETTINGS entries per
+ * SETTINGS frame that will be accepted. If more than those entries
+ * are received, the peer is considered to be misbehaving and session
+ * will be closed. The default value is 32.
+ */
+NGHTTP2_EXTERN void nghttp2_option_set_max_settings(nghttp2_option *option,
+                                                    size_t val);
 
 /**
  * @function
```
