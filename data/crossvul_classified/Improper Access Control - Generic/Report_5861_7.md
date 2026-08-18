# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5861_7
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5861_7`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 962-985 of the vulnerable file.

aes_err:
	goto out;
}

static void __exit aes_s390_fini(void)
{
	if (ctr_aes_alg_reg) {
		crypto_unregister_alg(&ctr_aes_alg);
		free_page((unsigned long) ctrblk);
	}
	if (xts_aes_alg_reg)
		crypto_unregister_alg(&xts_aes_alg);
	crypto_unregister_alg(&cbc_aes_alg);
	crypto_unregister_alg(&ecb_aes_alg);
	crypto_unregister_alg(&aes_alg);
}

module_init(aes_s390_init);
module_exit(aes_s390_fini);

MODULE_ALIAS("aes-all");

MODULE_DESCRIPTION("Rijndael (AES) Cipher Algorithm");
MODULE_LICENSE("GPL");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -979,7 +979,7 @@
 module_init(aes_s390_init);
 module_exit(aes_s390_fini);
 
-MODULE_ALIAS("aes-all");
+MODULE_ALIAS_CRYPTO("aes-all");
 
 MODULE_DESCRIPTION("Rijndael (AES) Cipher Algorithm");
 MODULE_LICENSE("GPL");
```
