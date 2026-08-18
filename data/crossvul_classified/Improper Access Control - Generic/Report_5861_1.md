# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5861_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5861_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 154-175 of the vulnerable file.

};


static int __init sha1_mod_init(void)
{
	return crypto_register_shash(&alg);
}


static void __exit sha1_mod_fini(void)
{
	crypto_unregister_shash(&alg);
}


module_init(sha1_mod_init);
module_exit(sha1_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA1 Secure Hash Algorithm (ARM)");
MODULE_ALIAS("sha1");
MODULE_AUTHOR("David McCullough <ucdevel@gmail.com>");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,5 +171,5 @@
 
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("SHA1 Secure Hash Algorithm (ARM)");
-MODULE_ALIAS("sha1");
+MODULE_ALIAS_CRYPTO("sha1");
 MODULE_AUTHOR("David McCullough <ucdevel@gmail.com>");
```
