# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4057_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4057_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 251-291 of the vulnerable file.

      xi->crl = NULL;
      count++;
    }
  }

  sk_X509_INFO_pop_free(xis, X509_INFO_free);

  if (count > 0)
    return TRUE;
  else
    return FALSE;
}

static SSL *
open_ssl_connection (rfbClient *client, int sockfd, rfbBool anonTLS, rfbCredential *cred)
{
  SSL_CTX *ssl_ctx = NULL;
  SSL *ssl = NULL;
  int n, finished = 0;
  X509_VERIFY_PARAM *param;
  uint8_t verify_crls = cred->x509Credential.x509CrlVerifyMode;

  if (!(ssl_ctx = SSL_CTX_new(SSLv23_client_method())))
  {
    rfbClientLog("Could not create new SSL context.\n");
    return NULL;
  }

  param = X509_VERIFY_PARAM_new();

  /* Setup verification if not anonymous */
  if (!anonTLS)
  {
    if (cred->x509Credential.x509CACertFile)
    {
      if (!SSL_CTX_load_verify_locations(ssl_ctx, cred->x509Credential.x509CACertFile, NULL))
      {
        rfbClientLog("Failed to load CA certificate from %s.\n",
                     cred->x509Credential.x509CACertFile);
        goto error_free_ctx;
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -268,7 +268,7 @@
   SSL *ssl = NULL;
   int n, finished = 0;
   X509_VERIFY_PARAM *param;
-  uint8_t verify_crls = cred->x509Credential.x509CrlVerifyMode;
+  uint8_t verify_crls;
 
   if (!(ssl_ctx = SSL_CTX_new(SSLv23_client_method())))
   {
@@ -281,6 +281,7 @@
   /* Setup verification if not anonymous */
   if (!anonTLS)
   {
+    verify_crls = cred->x509Credential.x509CrlVerifyMode;
     if (cred->x509Credential.x509CACertFile)
     {
       if (!SSL_CTX_load_verify_locations(ssl_ctx, cred->x509Credential.x509CACertFile, NULL))
```
