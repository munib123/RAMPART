# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2197_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2197_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 52-92 of the vulnerable file.

    size_t cksum_len = 0;
    size_t conflen = 0;
    int direction;
    krb5_ui_4 seqnum;
    OM_uint32 retval;
    size_t sumlen;
    krb5_keyusage sign_usage = KG_USAGE_SIGN;

    md5cksum.length = cksum.length = 0;
    md5cksum.contents = cksum.contents = NULL;

    header = kg_locate_header_iov(iov, iov_count, toktype);
    assert(header != NULL);

    trailer = kg_locate_iov(iov, iov_count, GSS_IOV_BUFFER_TYPE_TRAILER);
    if (trailer != NULL && trailer->buffer.length != 0) {
        *minor_status = (OM_uint32)KRB5_BAD_MSIZE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (header->buffer.length < token_wrapper_len + 14) {
        *minor_status = 0;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    ptr = (unsigned char *)header->buffer.value + token_wrapper_len;

    signalg  = ptr[0];
    signalg |= ptr[1] << 8;

    sealalg  = ptr[2];
    sealalg |= ptr[3] << 8;

    if (ptr[4] != 0xFF || ptr[5] != 0xFF) {
        *minor_status = 0;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (toktype != KG_TOK_WRAP_MSG && sealalg != 0xFFFF) {
        *minor_status = 0;
        return GSS_S_DEFECTIVE_TOKEN;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,7 +69,14 @@
         return GSS_S_DEFECTIVE_TOKEN;
     }
 
-    if (header->buffer.length < token_wrapper_len + 14) {
+    if (ctx->seq == NULL) {
+        /* ctx was established using a newer enctype, and cannot process RFC
+         * 1964 tokens. */
+        *minor_status = 0;
+        return GSS_S_DEFECTIVE_TOKEN;
+    }
+
+    if (header->buffer.length < token_wrapper_len + 22) {
         *minor_status = 0;
         return GSS_S_DEFECTIVE_TOKEN;
     }
```
