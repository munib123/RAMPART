# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2834_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2834_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 4985-5036 of the vulnerable file.

    }

    /* Make sure usage exists before checking bits */
    X509_check_ca(x);
    usage = X509_get_ext_d2i(x, NID_key_usage, NULL, NULL);
    if (usage) {
        if (!ku_reject(x, X509v3_KU_DIGITAL_SIGNATURE))
            ku_bits |= PKINIT_KU_DIGITALSIGNATURE;
        if (!ku_reject(x, X509v3_KU_KEY_ENCIPHERMENT))
            ku_bits |= PKINIT_KU_KEYENCIPHERMENT;
        ASN1_BIT_STRING_free(usage);
    }

    pkiDebug("%s: returning ku 0x%08x\n", __FUNCTION__, ku_bits);
    *ret_ku_bits = ku_bits;
    retval = 0;
out:
    return retval;
}

/*
 * Return a string format of an X509_NAME in buf where
 * size is an in/out parameter.  On input it is the size
 * of the buffer, and on output it is the actual length
 * of the name.
 * If buf is NULL, returns the length req'd to hold name
 */
static char *
X509_NAME_oneline_ex(X509_NAME * a,
                     char *buf,
                     unsigned int *size,
                     unsigned long flag)
{
    BIO *out = NULL;

    out = BIO_new(BIO_s_mem ());
    if (X509_NAME_print_ex(out, a, 0, flag) > 0) {
        if (buf != NULL && (*size) >  (unsigned int) BIO_number_written(out)) {
            memset(buf, 0, *size);
            BIO_read(out, buf, (int) BIO_number_written(out));
        }
        else {
            *size = BIO_number_written(out);
        }
    }
    BIO_free(out);
    return (buf);
}

/*
 * Get number of certificates available after crypto_load_certs()
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5002,33 +5002,29 @@
     return retval;
 }
 
-/*
- * Return a string format of an X509_NAME in buf where
- * size is an in/out parameter.  On input it is the size
- * of the buffer, and on output it is the actual length
- * of the name.
- * If buf is NULL, returns the length req'd to hold name
- */
-static char *
-X509_NAME_oneline_ex(X509_NAME * a,
-                     char *buf,
-                     unsigned int *size,
-                     unsigned long flag)
-{
-    BIO *out = NULL;
-
-    out = BIO_new(BIO_s_mem ());
-    if (X509_NAME_print_ex(out, a, 0, flag) > 0) {
-        if (buf != NULL && (*size) >  (unsigned int) BIO_number_written(out)) {
-            memset(buf, 0, *size);
-            BIO_read(out, buf, (int) BIO_number_written(out));
-        }
-        else {
-            *size = BIO_number_written(out);
-        }
-    }
-    BIO_free(out);
-    return (buf);
+static krb5_error_code
+rfc2253_name(X509_NAME *name, char **str_out)
+{
+    BIO *b = NULL;
+    char *str;
+
+    *str_out = NULL;
+    b = BIO_new(BIO_s_mem());
+    if (b == NULL)
+        return ENOMEM;
+    if (X509_NAME_print_ex(b, name, 0, XN_FLAG_SEP_COMMA_PLUS) < 0)
+        goto error;
+    str = calloc(BIO_number_written(b) + 1, 1);
+    if (str == NULL)
+        goto error;
+    BIO_read(b, str, BIO_number_written(b));
+    BIO_free(b);
+    *str_out = str;
+    return 0;
+
+error:
+    BIO_free(b);
+    return ENOMEM;
 }
 
 /*
@@ -5094,8 +5090,6 @@
     pkinit_cert_matching_data *md = NULL;
     krb5_principal *pkinit_sans = NULL, *upn_sans = NULL;
     size_t i, j;
-    char buf[DN_BUF_LEN];
-    unsigned int bufsize = sizeof(buf);
 
     *md_out = NULL;
 
@@ -5103,23 +5097,12 @@
     if (md == NULL)
         goto cleanup;
 
-    /* Get the subject name (in rfc2253 format). */
-    X509_NAME_oneline_ex(X509_get_subject_name(cert), buf, &bufsize,
-                         XN_FLAG_SEP_COMMA_PLUS);
-    md->subject_dn = strdup(buf);
-    if (md->subject_dn == NULL) {
-        ret = ENOMEM;
-        goto cleanup;
-    }
-
-    /* Get the issuer name (in rfc2253 format). */
-    X509_NAME_oneline_ex(X509_get_issuer_name(cert), buf, &bufsize,
-                         XN_FLAG_SEP_COMMA_PLUS);
-    md->issuer_dn = strdup(buf);
-    if (md->issuer_dn == NULL) {
-        ret = ENOMEM;
-        goto cleanup;
-    }
+    ret = rfc2253_name(X509_get_subject_name(cert), &md->subject_dn);
+    if (ret)
+        goto cleanup;
+    ret = rfc2253_name(X509_get_issuer_name(cert), &md->issuer_dn);
+    if (ret)
+        goto cleanup;
 
     /* Get the SAN data. */
     ret = crypto_retrieve_X509_sans(context, plg_cryptoctx, req_cryptoctx,
```
