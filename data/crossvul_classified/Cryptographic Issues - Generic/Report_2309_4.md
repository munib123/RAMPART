# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 2309_4
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2309_4`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 56-96 of the vulnerable file.

 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <openssl/stack.h>
#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif

int X509_verify(X509 *a, EVP_PKEY *r)
	{
	return(ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF),a->sig_alg,
		a->signature,a->cert_info,r));
	}

int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r)
	{
	return( ASN1_item_verify(ASN1_ITEM_rptr(X509_REQ_INFO),
		a->sig_alg,a->signature,a->req_info,r));
	}

int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r)
	{
	return(ASN1_item_verify(ASN1_ITEM_rptr(NETSCAPE_SPKAC),
		a->sig_algor,a->signature,a->spkac,r));
	}

int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)
	{
	x->cert_info->enc.modified = 1;
	return(ASN1_item_sign(ASN1_ITEM_rptr(X509_CINF), x->cert_info->signature,
		x->sig_alg, x->signature, x->cert_info,pkey,md));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,6 +73,8 @@
 
 int X509_verify(X509 *a, EVP_PKEY *r)
 	{
+	if (X509_ALGOR_cmp(a->sig_alg, a->cert_info->signature))
+		return 0;
 	return(ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF),a->sig_alg,
 		a->signature,a->cert_info,r));
 	}
```
