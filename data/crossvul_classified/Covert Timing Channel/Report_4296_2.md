# CrossVul Fix Pair: Covert Timing Channel in python
**Pair ID:** 4296_2
**Vulnerability Class:** Covert Timing Channel
**CWE:** CWE-385
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4296_2`)

## Vulnerability Information & PoC

## Description
Covert Timing Channel - In some instances, knowing when data is transmitted between parties can provide a malicious user with privileged information.

## Vulnerable Code
```python
Lines 102-142 of the vulnerable file.

        res = backend._lib.EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, oaep_md)
        backend.openssl_assert(res > 0)

    if (
        isinstance(padding, OAEP)
        and padding._label is not None
        and len(padding._label) > 0
    ):
        # set0_rsa_oaep_label takes ownership of the char * so we need to
        # copy it into some new memory
        labelptr = backend._lib.OPENSSL_malloc(len(padding._label))
        backend.openssl_assert(labelptr != backend._ffi.NULL)
        backend._ffi.memmove(labelptr, padding._label, len(padding._label))
        res = backend._lib.EVP_PKEY_CTX_set0_rsa_oaep_label(
            pkey_ctx, labelptr, len(padding._label)
        )
        backend.openssl_assert(res == 1)

    outlen = backend._ffi.new("size_t *", buf_size)
    buf = backend._ffi.new("unsigned char[]", buf_size)
    res = crypt(pkey_ctx, buf, outlen, data, len(data))
    if res <= 0:
        _handle_rsa_enc_dec_error(backend, key)

    return backend._ffi.buffer(buf)[: outlen[0]]


def _handle_rsa_enc_dec_error(backend, key):
    errors = backend._consume_errors_with_text()
    if isinstance(key, _RSAPublicKey):
        raise ValueError(
            "Data too long for key size. Encrypt less data or use a "
            "larger key size.",
            errors,
        )
    else:
        raise ValueError("Decryption failed.", errors)


def _rsa_sig_determine_padding(backend, key, padding, algorithm):
    if not isinstance(padding, AsymmetricPadding):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -119,23 +119,19 @@
 
     outlen = backend._ffi.new("size_t *", buf_size)
     buf = backend._ffi.new("unsigned char[]", buf_size)
+    # Everything from this line onwards is written with the goal of being as
+    # constant-time as is practical given the constraints of Python and our
+    # API. See Bleichenbacher's '98 attack on RSA, and its many many variants.
+    # As such, you should not attempt to change this (particularly to "clean it
+    # up") without understanding why it was written this way (see
+    # Chesterton's Fence), and without measuring to verify you have not
+    # introduced observable time differences.
     res = crypt(pkey_ctx, buf, outlen, data, len(data))
+    resbuf = backend._ffi.buffer(buf)[: outlen[0]]
+    backend._lib.ERR_clear_error()
     if res <= 0:
-        _handle_rsa_enc_dec_error(backend, key)
-
-    return backend._ffi.buffer(buf)[: outlen[0]]
-
-
-def _handle_rsa_enc_dec_error(backend, key):
-    errors = backend._consume_errors_with_text()
-    if isinstance(key, _RSAPublicKey):
-        raise ValueError(
-            "Data too long for key size. Encrypt less data or use a "
-            "larger key size.",
-            errors,
-        )
-    else:
-        raise ValueError("Decryption failed.", errors)
+        raise ValueError("Encryption/decryption failed.")
+    return resbuf
 
 
 def _rsa_sig_determine_padding(backend, key, padding, algorithm):
```
