# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5714_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5714_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 475-515 of the vulnerable file.

	return TRUE;
}

BOOL security_encrypt(BYTE* data, int length, rdpRdp* rdp)
{
	if (rdp->encrypt_use_count >= 4096)
	{
		security_key_update(rdp->encrypt_key, rdp->encrypt_update_key, rdp->rc4_key_len);
		crypto_rc4_free(rdp->rc4_encrypt_key);
		rdp->rc4_encrypt_key = crypto_rc4_init(rdp->encrypt_key, rdp->rc4_key_len);
		rdp->encrypt_use_count = 0;
	}
	crypto_rc4(rdp->rc4_encrypt_key, length, data, data);
	rdp->encrypt_use_count++;
	rdp->encrypt_checksum_use_count++;
	return TRUE;
}

BOOL security_decrypt(BYTE* data, int length, rdpRdp* rdp)
{
	if (rdp->decrypt_use_count >= 4096)
	{
		security_key_update(rdp->decrypt_key, rdp->decrypt_update_key, rdp->rc4_key_len);
		crypto_rc4_free(rdp->rc4_decrypt_key);
		rdp->rc4_decrypt_key = crypto_rc4_init(rdp->decrypt_key, rdp->rc4_key_len);
		rdp->decrypt_use_count = 0;
	}
	crypto_rc4(rdp->rc4_decrypt_key, length, data, data);
	rdp->decrypt_use_count += 1;
	rdp->decrypt_checksum_use_count++;
	return TRUE;
}

void security_hmac_signature(const BYTE* data, int length, BYTE* output, rdpRdp* rdp)
{
	BYTE buf[20];
	BYTE use_count_le[4];

	security_UINT32_le(use_count_le, rdp->encrypt_use_count);

	crypto_hmac_sha1_init(rdp->fips_hmac, rdp->fips_sign_key, 20);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -492,6 +492,8 @@
 
 BOOL security_decrypt(BYTE* data, int length, rdpRdp* rdp)
 {
+	if (rdp->rc4_decrypt_key == NULL)
+		return FALSE;
 	if (rdp->decrypt_use_count >= 4096)
 	{
 		security_key_update(rdp->decrypt_key, rdp->decrypt_update_key, rdp->rc4_key_len);
```
