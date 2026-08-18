# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5636_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5636_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 47-87 of the vulnerable file.

 *
 * If buf->len is <= 0 we should return
 * If buf->len is set to 0 on exit it tells the caller to ignore the packet.
 *
 * work is a workspace buffer we are given of size BUF_SIZE.
 * work may be used to return output data, or the input buffer
 * may be modified and returned as output.  If output data is
 * returned in work, the data should start after FRAME_HEADROOM bytes
 * of padding to leave room for downstream routines to prepend.
 *
 * Up to a total of FRAME_HEADROOM bytes may be prepended to the input buf
 * by all routines (encryption, decryption, compression, and decompression).
 *
 * Note that the buf_prepend return will assert if we try to
 * make a header bigger than FRAME_HEADROOM.  This should not
 * happen unless the frame parameters are wrong.
 */

#define CRYPT_ERROR(format) \
  do { msg (D_CRYPT_ERRORS, "%s: " format, error_prefix); goto error_exit; } while (false)

void
openvpn_encrypt (struct buffer *buf, struct buffer work,
		 const struct crypto_options *opt,
		 const struct frame* frame)
{
  struct gc_arena gc;
  gc_init (&gc);

  if (buf->len > 0 && opt->key_ctx_bi)
    {
      struct key_ctx *ctx = &opt->key_ctx_bi->encrypt;

      /* Do Encrypt from buf -> work */
      if (ctx->cipher)
	{
	  uint8_t iv_buf[OPENVPN_MAX_IV_LENGTH];
	  const int iv_size = cipher_ctx_iv_length (ctx->cipher);
	  const unsigned int mode = cipher_ctx_mode (ctx->cipher);
	  int outlen;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,6 +65,24 @@
 #define CRYPT_ERROR(format) \
   do { msg (D_CRYPT_ERRORS, "%s: " format, error_prefix); goto error_exit; } while (false)
 
+/**
+ * As memcmp(), but constant-time.
+ * Returns 0 when data is equal, non-zero otherwise.
+ */
+static int
+memcmp_constant_time (const void *a, const void *b, size_t size) {
+  const uint8_t * a1 = a;
+  const uint8_t * b1 = b;
+  int ret = 0;
+  size_t i;
+
+  for (i = 0; i < size; i++) {
+      ret |= *a1++ ^ *b1++;
+  }
+
+  return ret;
+}
+
 void
 openvpn_encrypt (struct buffer *buf, struct buffer work,
 		 const struct crypto_options *opt,
@@ -244,7 +262,7 @@
 	  hmac_ctx_final (ctx->hmac, local_hmac);
 
 	  /* Compare locally computed HMAC with packet HMAC */
-	  if (memcmp (local_hmac, BPTR (buf), hmac_len))
+	  if (memcmp_constant_time (local_hmac, BPTR (buf), hmac_len))
 	    CRYPT_ERROR ("packet HMAC authentication failed");
 
 	  ASSERT (buf_advance (buf, hmac_len));
```
