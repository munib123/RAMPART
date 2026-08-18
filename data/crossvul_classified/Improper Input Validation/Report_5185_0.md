# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5185_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5185_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.


  /* make sure the output is the right size */
  if (x != siglen) {
     XFREE(tmpbuf);
     return CRYPT_INVALID_PACKET;
  }

  if (padding == LTC_PKCS_1_PSS) {
    /* PSS decode and verify it */

    if(modulus_bitlen%8 == 1){
      err = pkcs_1_pss_decode(hash, hashlen, tmpbuf+1, x-1, saltlen, hash_idx, modulus_bitlen, stat);
    }
    else{
      err = pkcs_1_pss_decode(hash, hashlen, tmpbuf, x, saltlen, hash_idx, modulus_bitlen, stat);
    }

  } else {
    /* PKCS #1 v1.5 decode it */
    unsigned char *out;
    unsigned long outlen, loid[16];
    int           decoded;
    ltc_asn1_list digestinfo[2], siginfo[2];

    /* not all hashes have OIDs... so sad */
    if (hash_descriptor[hash_idx].OIDlen == 0) {
       err = CRYPT_INVALID_ARG;
       goto bail_2;
    }

    /* allocate temp buffer for decoded hash */
    outlen = ((modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0)) - 3;
    out    = XMALLOC(outlen);
    if (out == NULL) {
      err = CRYPT_MEM;
      goto bail_2;
    }

    if ((err = pkcs_1_v1_5_decode(tmpbuf, x, LTC_PKCS_1_EMSA, modulus_bitlen, out, &outlen, &decoded)) != CRYPT_OK) {
      XFREE(out);
      goto bail_2;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,7 +103,7 @@
   } else {
     /* PKCS #1 v1.5 decode it */
     unsigned char *out;
-    unsigned long outlen, loid[16];
+    unsigned long outlen, loid[16], reallen;
     int           decoded;
     ltc_asn1_list digestinfo[2], siginfo[2];
 
@@ -145,8 +145,14 @@
        goto bail_2;
     }
 
+    if ((err = der_length_sequence(siginfo, 2, &reallen)) != CRYPT_OK) {
+       XFREE(out);
+       goto bail_2;
+    }
+
     /* test OID */
-    if ((digestinfo[0].size == hash_descriptor[hash_idx].OIDlen) &&
+    if ((reallen == outlen) &&
+        (digestinfo[0].size == hash_descriptor[hash_idx].OIDlen) &&
         (XMEMCMP(digestinfo[0].data, hash_descriptor[hash_idx].OID, sizeof(unsigned long) * hash_descriptor[hash_idx].OIDlen) == 0) &&
         (siginfo[1].size == hashlen) &&
         (XMEMCMP(siginfo[1].data, hash, hashlen) == 0)) {
```
