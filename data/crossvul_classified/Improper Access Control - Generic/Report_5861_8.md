# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5861_8
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5861_8`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 602-626 of the vulnerable file.

}

static void __exit des_s390_exit(void)
{
	if (ctrblk) {
		crypto_unregister_alg(&ctr_des_alg);
		crypto_unregister_alg(&ctr_des3_alg);
		free_page((unsigned long) ctrblk);
	}
	crypto_unregister_alg(&cbc_des3_alg);
	crypto_unregister_alg(&ecb_des3_alg);
	crypto_unregister_alg(&des3_alg);
	crypto_unregister_alg(&cbc_des_alg);
	crypto_unregister_alg(&ecb_des_alg);
	crypto_unregister_alg(&des_alg);
}

module_init(des_s390_init);
module_exit(des_s390_exit);

MODULE_ALIAS("des");
MODULE_ALIAS("des3_ede");

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DES & Triple DES EDE Cipher Algorithms");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -619,8 +619,8 @@
 module_init(des_s390_init);
 module_exit(des_s390_exit);
 
-MODULE_ALIAS("des");
-MODULE_ALIAS("des3_ede");
+MODULE_ALIAS_CRYPTO("des");
+MODULE_ALIAS_CRYPTO("des3_ede");
 
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("DES & Triple DES EDE Cipher Algorithms");
```
