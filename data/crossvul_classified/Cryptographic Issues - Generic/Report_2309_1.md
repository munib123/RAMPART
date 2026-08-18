# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 2309_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2309_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 73-113 of the vulnerable file.

#include "asn1_locl.h"

#ifndef NO_ASN1_OLD

int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *a, ASN1_BIT_STRING *signature,
		char *data, EVP_PKEY *pkey)
	{
	EVP_MD_CTX ctx;
	const EVP_MD *type;
	unsigned char *p,*buf_in=NULL;
	int ret= -1,i,inl;

	EVP_MD_CTX_init(&ctx);
	i=OBJ_obj2nid(a->algorithm);
	type=EVP_get_digestbyname(OBJ_nid2sn(i));
	if (type == NULL)
		{
		ASN1err(ASN1_F_ASN1_VERIFY,ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
		goto err;
		}
	
	inl=i2d(data,NULL);
	buf_in=OPENSSL_malloc((unsigned int)inl);
	if (buf_in == NULL)
		{
		ASN1err(ASN1_F_ASN1_VERIFY,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	p=buf_in;

	i2d(data,&p);
	ret=
		EVP_VerifyInit_ex(&ctx,type, NULL)
		&& EVP_VerifyUpdate(&ctx,(unsigned char *)buf_in,inl);

	OPENSSL_cleanse(buf_in,(unsigned int)inl);
	OPENSSL_free(buf_in);

	if (!ret)
		{
		ASN1err(ASN1_F_ASN1_VERIFY,ERR_R_EVP_LIB);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,6 +90,12 @@
 		ASN1err(ASN1_F_ASN1_VERIFY,ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM);
 		goto err;
 		}
+
+	if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7)
+		{
+		ASN1err(ASN1_F_ASN1_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
+		goto err;
+		}
 	
 	inl=i2d(data,NULL);
 	buf_in=OPENSSL_malloc((unsigned int)inl);
@@ -150,6 +156,12 @@
 		return -1;
 		}
 
+	if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7)
+		{
+		ASN1err(ASN1_F_ASN1_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
+		return -1;
+		}
+
 	EVP_MD_CTX_init(&ctx);
 
 	/* Convert signature OID into digest and public key OIDs */
```
