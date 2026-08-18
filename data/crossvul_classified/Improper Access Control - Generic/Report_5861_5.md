# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5861_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5861_5`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 21-64 of the vulnerable file.

#define PRIO			300
#define aes_ecb_encrypt		ce_aes_ecb_encrypt
#define aes_ecb_decrypt		ce_aes_ecb_decrypt
#define aes_cbc_encrypt		ce_aes_cbc_encrypt
#define aes_cbc_decrypt		ce_aes_cbc_decrypt
#define aes_ctr_encrypt		ce_aes_ctr_encrypt
#define aes_xts_encrypt		ce_aes_xts_encrypt
#define aes_xts_decrypt		ce_aes_xts_decrypt
MODULE_DESCRIPTION("AES-ECB/CBC/CTR/XTS using ARMv8 Crypto Extensions");
#else
#define MODE			"neon"
#define PRIO			200
#define aes_ecb_encrypt		neon_aes_ecb_encrypt
#define aes_ecb_decrypt		neon_aes_ecb_decrypt
#define aes_cbc_encrypt		neon_aes_cbc_encrypt
#define aes_cbc_decrypt		neon_aes_cbc_decrypt
#define aes_ctr_encrypt		neon_aes_ctr_encrypt
#define aes_xts_encrypt		neon_aes_xts_encrypt
#define aes_xts_decrypt		neon_aes_xts_decrypt
MODULE_DESCRIPTION("AES-ECB/CBC/CTR/XTS using ARMv8 NEON");
MODULE_ALIAS("ecb(aes)");
MODULE_ALIAS("cbc(aes)");
MODULE_ALIAS("ctr(aes)");
MODULE_ALIAS("xts(aes)");
#endif

MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");

/* defined in aes-modes.S */
asmlinkage void aes_ecb_encrypt(u8 out[], u8 const in[], u8 const rk[],
				int rounds, int blocks, int first);
asmlinkage void aes_ecb_decrypt(u8 out[], u8 const in[], u8 const rk[],
				int rounds, int blocks, int first);

asmlinkage void aes_cbc_encrypt(u8 out[], u8 const in[], u8 const rk[],
				int rounds, int blocks, u8 iv[], int first);
asmlinkage void aes_cbc_decrypt(u8 out[], u8 const in[], u8 const rk[],
				int rounds, int blocks, u8 iv[], int first);

asmlinkage void aes_ctr_encrypt(u8 out[], u8 const in[], u8 const rk[],
				int rounds, int blocks, u8 ctr[], int first);

asmlinkage void aes_xts_encrypt(u8 out[], u8 const in[], u8 const rk1[],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,10 +38,10 @@
 #define aes_xts_encrypt		neon_aes_xts_encrypt
 #define aes_xts_decrypt		neon_aes_xts_decrypt
 MODULE_DESCRIPTION("AES-ECB/CBC/CTR/XTS using ARMv8 NEON");
-MODULE_ALIAS("ecb(aes)");
-MODULE_ALIAS("cbc(aes)");
-MODULE_ALIAS("ctr(aes)");
-MODULE_ALIAS("xts(aes)");
+MODULE_ALIAS_CRYPTO("ecb(aes)");
+MODULE_ALIAS_CRYPTO("cbc(aes)");
+MODULE_ALIAS_CRYPTO("ctr(aes)");
+MODULE_ALIAS_CRYPTO("xts(aes)");
 #endif
 
 MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
```
