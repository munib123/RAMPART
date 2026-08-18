# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3070_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3070_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 378-418 of the vulnerable file.

     */
    if (wb->left != 0) {
        i = ssl3_write_pending(s, type, &buf[tot], s->rlayer.wpend_tot);
        if (i <= 0) {
            /* XXX should we ssl3_release_write_buffer if i<0? */
            s->rlayer.wnum = tot;
            return i;
        }
        tot += i;               /* this might be last fragment */
    }
#if !defined(OPENSSL_NO_MULTIBLOCK) && EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
    /*
     * Depending on platform multi-block can deliver several *times*
     * better performance. Downside is that it has to allocate
     * jumbo buffer to accommodate up to 8 records, but the
     * compromise is considered worthy.
     */
    if (type == SSL3_RT_APPLICATION_DATA &&
        u_len >= 4 * (max_send_fragment = s->max_send_fragment) &&
        s->compress == NULL && s->msg_callback == NULL &&
        !SSL_USE_ETM(s) && SSL_USE_EXPLICIT_IV(s) &&
        EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(s->enc_write_ctx)) &
        EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK) {
        unsigned char aad[13];
        EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM mb_param;
        int packlen;

        /* minimize address aliasing conflicts */
        if ((max_send_fragment & 0xfff) == 0)
            max_send_fragment -= 512;

        if (tot == 0 || wb->buf == NULL) { /* allocate jumbo buffer */
            ssl3_release_write_buffer(s);

            packlen = EVP_CIPHER_CTX_ctrl(s->enc_write_ctx,
                                          EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE,
                                          max_send_fragment, NULL);

            if (u_len >= 8 * max_send_fragment)
                packlen *= 8;
            else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -395,7 +395,7 @@
     if (type == SSL3_RT_APPLICATION_DATA &&
         u_len >= 4 * (max_send_fragment = s->max_send_fragment) &&
         s->compress == NULL && s->msg_callback == NULL &&
-        !SSL_USE_ETM(s) && SSL_USE_EXPLICIT_IV(s) &&
+        !SSL_WRITE_ETM(s) && SSL_USE_EXPLICIT_IV(s) &&
         EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(s->enc_write_ctx)) &
         EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK) {
         unsigned char aad[13];
@@ -791,7 +791,7 @@
          * wb->buf
          */
 
-        if (!SSL_USE_ETM(s) && mac_size != 0) {
+        if (!SSL_WRITE_ETM(s) && mac_size != 0) {
             if (s->method->ssl3_enc->mac(s, &wr[j],
                                          &(outbuf[j][wr[j].length + eivlen]),
                                          1) < 0)
@@ -814,7 +814,7 @@
         goto err;
 
     for (j = 0; j < numpipes; j++) {
-        if (SSL_USE_ETM(s) && mac_size != 0) {
+        if (SSL_WRITE_ETM(s) && mac_size != 0) {
             if (s->method->ssl3_enc->mac(s, &wr[j],
                                          outbuf[j] + wr[j].length, 1) < 0)
                 goto err;
```
