# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4027_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4027_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 799-839 of the vulnerable file.

BOOL security_fips_encrypt(BYTE* data, size_t length, rdpRdp* rdp)
{
	BOOL rc = FALSE;
	size_t olen;

	EnterCriticalSection(&rdp->critical);
	if (!winpr_Cipher_Update(rdp->fips_encrypt, data, length, data, &olen))
		goto fail;

	rdp->encrypt_use_count++;
	rc = TRUE;
fail:
	LeaveCriticalSection(&rdp->critical);
	return rc;
}

BOOL security_fips_decrypt(BYTE* data, size_t length, rdpRdp* rdp)
{
	size_t olen;

	if (!winpr_Cipher_Update(rdp->fips_decrypt, data, length, data, &olen))
		return FALSE;

	return TRUE;
}

BOOL security_fips_check_signature(const BYTE* data, size_t length, const BYTE* sig, rdpRdp* rdp)
{
	BYTE buf[WINPR_SHA1_DIGEST_LENGTH];
	BYTE use_count_le[4];
	WINPR_HMAC_CTX* hmac;
	BOOL result = FALSE;
	security_UINT32_le(use_count_le, rdp->decrypt_use_count);

	if (!(hmac = winpr_HMAC_New()))
		return FALSE;

	if (!winpr_HMAC_Init(hmac, WINPR_MD_SHA1, rdp->fips_sign_key, WINPR_SHA1_DIGEST_LENGTH))
		goto out;

	if (!winpr_HMAC_Update(hmac, data, length))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -816,6 +816,9 @@
 {
 	size_t olen;
 
+	if (!rdp || !rdp->fips_decrypt)
+		return FALSE;
+
 	if (!winpr_Cipher_Update(rdp->fips_decrypt, data, length, data, &olen))
 		return FALSE;
 
```
