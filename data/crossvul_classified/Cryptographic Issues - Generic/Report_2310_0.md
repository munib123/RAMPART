# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 2310_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2310_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 141-181 of the vulnerable file.

#endif


int ASN1_item_verify(const ASN1_ITEM *it, X509_ALGOR *a,
		ASN1_BIT_STRING *signature, void *asn, EVP_PKEY *pkey)
	{
	EVP_MD_CTX ctx;
	unsigned char *buf_in=NULL;
	int ret= -1,inl;

	int mdnid, pknid;

	if (!pkey)
		{
		ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ERR_R_PASSED_NULL_PARAMETER);
		return -1;
		}

	if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7)
		{
		ASN1err(ASN1_F_ASN1_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
		return -1;
		}

	EVP_MD_CTX_init(&ctx);

	/* Convert signature OID into digest and public key OIDs */
	if (!OBJ_find_sigid_algs(OBJ_obj2nid(a->algorithm), &mdnid, &pknid))
		{
		ASN1err(ASN1_F_ASN1_ITEM_VERIFY,ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
		goto err;
		}
	if (mdnid == NID_undef)
		{
		if (!pkey->ameth || !pkey->ameth->item_verify)
			{
			ASN1err(ASN1_F_ASN1_ITEM_VERIFY,ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM);
			goto err;
			}
		ret = pkey->ameth->item_verify(&ctx, it, asn, a,
							signature, pkey);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,7 +158,7 @@
 
 	if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7)
 		{
-		ASN1err(ASN1_F_ASN1_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
+		ASN1err(ASN1_F_ASN1_ITEM_VERIFY, ASN1_R_INVALID_BIT_STRING_BITS_LEFT);
 		return -1;
 		}
 
```
