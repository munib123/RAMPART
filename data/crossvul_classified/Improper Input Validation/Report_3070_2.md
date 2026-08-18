# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3070_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3070_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 329-369 of the vulnerable file.

        /* Mark this record as not read by upper layers yet */
        rr[num_recs].read = 0;

        num_recs++;

        /* we have pulled in a full packet so zero things */
        RECORD_LAYER_reset_packet_length(&s->rlayer);
        RECORD_LAYER_clear_first_record(&s->rlayer);
    } while (num_recs < max_recs
             && rr[num_recs - 1].type == SSL3_RT_APPLICATION_DATA
             && SSL_USE_EXPLICIT_IV(s)
             && s->enc_read_ctx != NULL
             && (EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(s->enc_read_ctx))
                 & EVP_CIPH_FLAG_PIPELINE)
             && ssl3_record_app_data_waiting(s));

    /*
     * If in encrypt-then-mac mode calculate mac from encrypted record. All
     * the details below are public so no timing details can leak.
     */
    if (SSL_USE_ETM(s) && s->read_hash) {
        unsigned char *mac;
        mac_size = EVP_MD_CTX_size(s->read_hash);
        OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);
        for (j = 0; j < num_recs; j++) {
            if (rr[j].length < mac_size) {
                al = SSL_AD_DECODE_ERROR;
                SSLerr(SSL_F_SSL3_GET_RECORD, SSL_R_LENGTH_TOO_SHORT);
                goto f_err;
            }
            rr[j].length -= mac_size;
            mac = rr[j].data + rr[j].length;
            i = s->method->ssl3_enc->mac(s, &rr[j], md, 0 /* not send */ );
            if (i < 0 || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0) {
                al = SSL_AD_BAD_RECORD_MAC;
                SSLerr(SSL_F_SSL3_GET_RECORD,
                       SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
                goto f_err;
            }
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -346,7 +346,7 @@
      * If in encrypt-then-mac mode calculate mac from encrypted record. All
      * the details below are public so no timing details can leak.
      */
-    if (SSL_USE_ETM(s) && s->read_hash) {
+    if (SSL_READ_ETM(s) && s->read_hash) {
         unsigned char *mac;
         mac_size = EVP_MD_CTX_size(s->read_hash);
         OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);
@@ -393,7 +393,7 @@
     /* r->length is now the compressed data plus mac */
     if ((sess != NULL) &&
         (s->enc_read_ctx != NULL) &&
-        (EVP_MD_CTX_md(s->read_hash) != NULL) && !SSL_USE_ETM(s)) {
+        (!SSL_READ_ETM(s) && EVP_MD_CTX_md(s->read_hash) != NULL)) {
         /* s->read_hash != NULL => mac_size != -1 */
         unsigned char *mac = NULL;
         unsigned char mac_tmp[EVP_MAX_MD_SIZE];
@@ -823,7 +823,7 @@
         }
 
         ret = 1;
-        if (!SSL_USE_ETM(s) && EVP_MD_CTX_md(s->read_hash) != NULL)
+        if (!SSL_READ_ETM(s) && EVP_MD_CTX_md(s->read_hash) != NULL)
             mac_size = EVP_MD_CTX_size(s->read_hash);
         if ((bs != 1) && !send) {
             int tmpret;
@@ -997,7 +997,7 @@
     header[11] = (rec->length) >> 8;
     header[12] = (rec->length) & 0xff;
 
-    if (!send && !SSL_USE_ETM(ssl) &&
+    if (!send && !SSL_READ_ETM(ssl) &&
         EVP_CIPHER_CTX_mode(ssl->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
         ssl3_cbc_record_digest_supported(mac_ctx)) {
         /*
@@ -1022,7 +1022,7 @@
             EVP_MD_CTX_free(hmac);
             return -1;
         }
-        if (!send && !SSL_USE_ETM(ssl) && FIPS_mode())
+        if (!send && !SSL_READ_ETM(ssl) && FIPS_mode())
             if (!tls_fips_digest_extra(ssl->enc_read_ctx,
                                        mac_ctx, rec->input,
                                        rec->length, rec->orig_len)) {
```
