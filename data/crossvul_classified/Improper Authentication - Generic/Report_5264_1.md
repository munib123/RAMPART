# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 5264_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5264_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 985-1025 of the vulnerable file.

  default:
    /* OOM, etc. */
    break;
  }

  return result;
}

/**
 *
 * Callback to pick the SSL client certificate.
 */
static SECStatus SelectClientCert(void *arg, PRFileDesc *sock,
                                  struct CERTDistNamesStr *caNames,
                                  struct CERTCertificateStr **pRetCert,
                                  struct SECKEYPrivateKeyStr **pRetKey)
{
  struct ssl_connect_data *connssl = (struct ssl_connect_data *)arg;
  struct Curl_easy *data = connssl->data;
  const char *nickname = connssl->client_nickname;

  if(connssl->obj_clicert) {
    /* use the cert/key provided by PEM reader */
    static const char pem_slotname[] = "PEM Token #1";
    SECItem cert_der = { 0, NULL, 0 };
    void *proto_win = SSL_RevealPinArg(sock);
    struct CERTCertificateStr *cert;
    struct SECKEYPrivateKeyStr *key;

    PK11SlotInfo *slot = PK11_FindSlotByName(pem_slotname);
    if(NULL == slot) {
      failf(data, "NSS: PK11 slot not found: %s", pem_slotname);
      return SECFailure;
    }

    if(PK11_ReadRawAttribute(PK11_TypeGeneric, connssl->obj_clicert, CKA_VALUE,
                             &cert_der) != SECSuccess) {
      failf(data, "NSS: CKA_VALUE not found in PK11 generic object");
      PK11_FreeSlot(slot);
      return SECFailure;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1002,10 +1002,10 @@
   struct ssl_connect_data *connssl = (struct ssl_connect_data *)arg;
   struct Curl_easy *data = connssl->data;
   const char *nickname = connssl->client_nickname;
+  static const char pem_slotname[] = "PEM Token #1";
 
   if(connssl->obj_clicert) {
     /* use the cert/key provided by PEM reader */
-    static const char pem_slotname[] = "PEM Token #1";
     SECItem cert_der = { 0, NULL, 0 };
     void *proto_win = SSL_RevealPinArg(sock);
     struct CERTCertificateStr *cert;
@@ -1066,6 +1066,12 @@
   nickname = (*pRetCert)->nickname;
   if(NULL == nickname)
     nickname = "[unknown]";
+
+  if(!strncmp(nickname, pem_slotname, sizeof(pem_slotname) - 1U)) {
+    failf(data, "NSS: refusing previously loaded certificate from file: %s",
+          nickname);
+    return SECFailure;
+  }
 
   if(NULL == *pRetKey) {
     failf(data, "NSS: private key not found for certificate: %s", nickname);
```
