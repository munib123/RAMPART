# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 117_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `117_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 182-217 of the vulnerable file.

            res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
                self._ctx, self._backend._lib.EVP_CTRL_AEAD_GET_TAG,
                self._block_size_bytes, tag_buf
            )
            self._backend.openssl_assert(res != 0)
            self._tag = self._backend._ffi.buffer(tag_buf)[:]

        res = self._backend._lib.EVP_CIPHER_CTX_cleanup(self._ctx)
        self._backend.openssl_assert(res == 1)
        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def finalize_with_tag(self, tag):
        if (
            self._backend._lib.CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 and
            not self._backend._lib.CRYPTOGRAPHY_IS_LIBRESSL
        ):
            raise NotImplementedError(
                "finalize_with_tag requires OpenSSL >= 1.0.2. To use this "
                "method please update OpenSSL"
            )
        res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
            self._ctx, self._backend._lib.EVP_CTRL_AEAD_SET_TAG,
            len(tag), tag
        )
        self._backend.openssl_assert(res != 0)
        self._tag = tag
        return self.finalize()

    def authenticate_additional_data(self, data):
        outlen = self._backend._ffi.new("int *")
        res = self._backend._lib.EVP_CipherUpdate(
            self._ctx, self._backend._ffi.NULL, outlen, data, len(data)
        )
        self._backend.openssl_assert(res != 0)

    tag = utils.read_only_property("_tag")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -199,6 +199,11 @@
                 "finalize_with_tag requires OpenSSL >= 1.0.2. To use this "
                 "method please update OpenSSL"
             )
+        if len(tag) < self._mode._min_tag_length:
+            raise ValueError(
+                "Authentication tag must be {0} bytes or longer.".format(
+                    self._mode._min_tag_length)
+            )
         res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
             self._ctx, self._backend._lib.EVP_CTRL_AEAD_SET_TAG,
             len(tag), tag
```
