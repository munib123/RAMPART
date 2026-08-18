# CrossVul Fix Pair: Operation on a Resource after Expiration or Release in c
**Pair ID:** 1298_0
**Vulnerability Class:** Operation on a Resource after Expiration or Release
**CWE:** CWE-672
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1298_0`)

## Vulnerability Information & PoC

## Description
Operation on a Resource after Expiration or Release - The product uses, accesses, or otherwise operates on a resource after that resource has been expired, released, or revoked.

## Vulnerable Code
```c
Lines 243-286 of the vulnerable file.

	sc_format_asn1_entry(asn1_com_key_attr + 1, &info.usage, &usage_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 2, &info.native, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 3, &info.access_flags, &af_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 4, &info.key_reference, NULL, 0);

	for (i=0; i<SC_MAX_SUPPORTED_ALGORITHMS && (asn1_supported_algorithms + i)->name; i++)
		sc_format_asn1_entry(asn1_supported_algorithms + i, &info.algo_refs[i], NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 5, asn1_supported_algorithms, NULL, 0);

	sc_format_asn1_entry(asn1_com_prkey_attr + 0, &info.subject.value, &info.subject.len, 0);

	/* Fill in defaults */
	memset(&info, 0, sizeof(info));
	info.key_reference = -1;
	info.native = 1;
	memset(gostr3410_params, 0, sizeof(gostr3410_params));

	r = sc_asn1_decode_choice(ctx, asn1_prkey, *buf, *buflen, buf, buflen);
	if (r < 0) {
		/* This might have allocated something. If so, clear it now */
		if (asn1_com_prkey_attr->flags & SC_ASN1_PRESENT &&
			asn1_com_prkey_attr[0].flags & SC_ASN1_PRESENT) {
			free(asn1_com_prkey_attr[0].parm);
		}
	}
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	LOG_TEST_RET(ctx, r, "PrKey DF ASN.1 decoding failed");
	if (asn1_prkey[0].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_RSA;
	}
	else if (asn1_prkey[1].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_EC;
	}
	else if (asn1_prkey[2].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_DSA;
		/* If the value was indirect-protected, mark the path */
		if (asn1_dsakey_i_p_attr[0].flags & SC_ASN1_PRESENT)
			info.path.type = SC_PATH_TYPE_PATH_PROT;
	}
	else if (asn1_prkey[3].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_GOSTR3410;
		assert(info.modulus_length == 0);
		info.modulus_length = SC_PKCS15_GOSTR3410_KEYSIZE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -260,10 +260,7 @@
 	r = sc_asn1_decode_choice(ctx, asn1_prkey, *buf, *buflen, buf, buflen);
 	if (r < 0) {
 		/* This might have allocated something. If so, clear it now */
-		if (asn1_com_prkey_attr->flags & SC_ASN1_PRESENT &&
-			asn1_com_prkey_attr[0].flags & SC_ASN1_PRESENT) {
-			free(asn1_com_prkey_attr[0].parm);
-		}
+		free(info.subject.value);
 	}
 	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
 		return r;
```
