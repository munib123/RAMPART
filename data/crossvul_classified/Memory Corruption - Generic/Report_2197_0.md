# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2197_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2197_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 57-97 of the vulnerable file.

/* message_buffer is an input if SIGN, output if SEAL, and ignored if DEL_CTX
   conf_state is only valid if SEAL. */

static OM_uint32
kg_unseal_v1(context, minor_status, ctx, ptr, bodysize, message_buffer,
             conf_state, qop_state, toktype)
    krb5_context context;
    OM_uint32 *minor_status;
    krb5_gss_ctx_id_rec *ctx;
    unsigned char *ptr;
    int bodysize;
    gss_buffer_t message_buffer;
    int *conf_state;
    gss_qop_t *qop_state;
    int toktype;
{
    krb5_error_code code;
    int conflen = 0;
    int signalg;
    int sealalg;
    gss_buffer_desc token;
    krb5_checksum cksum;
    krb5_checksum md5cksum;
    krb5_data plaind;
    char *data_ptr;
    unsigned char *plain;
    unsigned int cksum_len = 0;
    size_t plainlen;
    int direction;
    krb5_ui_4 seqnum;
    OM_uint32 retval;
    size_t sumlen;
    krb5_keyusage sign_usage = KG_USAGE_SIGN;

    if (toktype == KG_TOK_SEAL_MSG) {
        message_buffer->length = 0;
        message_buffer->value = NULL;
    }

    /* get the sign and seal algorithms */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,6 +74,7 @@
     int conflen = 0;
     int signalg;
     int sealalg;
+    int bad_pad = 0;
     gss_buffer_desc token;
     krb5_checksum cksum;
     krb5_checksum md5cksum;
@@ -86,6 +87,7 @@
     krb5_ui_4 seqnum;
     OM_uint32 retval;
     size_t sumlen;
+    size_t padlen;
     krb5_keyusage sign_usage = KG_USAGE_SIGN;
 
     if (toktype == KG_TOK_SEAL_MSG) {
@@ -93,17 +95,22 @@
         message_buffer->value = NULL;
     }
 
-    /* get the sign and seal algorithms */
+    /* Sanity checks */
+
+    if (ctx->seq == NULL) {
+        /* ctx was established using a newer enctype, and cannot process RFC
+         * 1964 tokens. */
+        *minor_status = 0;
+        return GSS_S_DEFECTIVE_TOKEN;
+    }
+
+    if ((bodysize < 22) || (ptr[4] != 0xff) || (ptr[5] != 0xff)) {
+        *minor_status = 0;
+        return GSS_S_DEFECTIVE_TOKEN;
+    }
 
     signalg = ptr[0] + (ptr[1]<<8);
     sealalg = ptr[2] + (ptr[3]<<8);
-
-    /* Sanity checks */
-
-    if ((ptr[4] != 0xff) || (ptr[5] != 0xff)) {
-        *minor_status = 0;
-        return GSS_S_DEFECTIVE_TOKEN;
-    }
 
     if ((toktype != KG_TOK_SEAL_MSG) &&
         (sealalg != 0xffff)) {
@@ -149,6 +156,11 @@
         cksum_len = 20;
         break;
     default:
+        *minor_status = 0;
+        return GSS_S_DEFECTIVE_TOKEN;
+    }
+
+    if ((size_t)bodysize < 14 + cksum_len) {
         *minor_status = 0;
         return GSS_S_DEFECTIVE_TOKEN;
     }
@@ -207,7 +219,20 @@
         plainlen = tmsglen;
 
         conflen = kg_confounder_size(context, ctx->enc->keyblock.enctype);
-        token.length = tmsglen - conflen - plain[tmsglen-1];
+        if (tmsglen < conflen) {
+            if (sealalg != 0xffff)
+                xfree(plain);
+            *minor_status = 0;
+            return(GSS_S_DEFECTIVE_TOKEN);
+        }
+        padlen = plain[tmsglen - 1];
+        if (tmsglen - conflen < padlen) {
+            /* Don't error out yet, to avoid padding oracle attacks.  We will
+             * treat this as a checksum failure later on. */
+            padlen = 0;
+            bad_pad = 1;
+        }
+        token.length = tmsglen - conflen - padlen;
 
         if (token.length) {
             if ((token.value = (void *) gssalloc_malloc(token.length)) == NULL) {
@@ -403,7 +428,7 @@
 
     /* compare the computed checksum against the transmitted checksum */
 
-    if (code) {
+    if (code || bad_pad) {
         if (toktype == KG_TOK_SEAL_MSG)
             gssalloc_free(token.value);
         *minor_status = 0;
```
