# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5861_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5861_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 177-197 of the vulnerable file.

};

static int __init sha1_neon_mod_init(void)
{
	if (!cpu_has_neon())
		return -ENODEV;

	return crypto_register_shash(&alg);
}

static void __exit sha1_neon_mod_fini(void)
{
	crypto_unregister_shash(&alg);
}

module_init(sha1_neon_mod_init);
module_exit(sha1_neon_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA1 Secure Hash Algorithm, NEON accelerated");
MODULE_ALIAS("sha1");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,4 +194,4 @@
 
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("SHA1 Secure Hash Algorithm, NEON accelerated");
-MODULE_ALIAS("sha1");
+MODULE_ALIAS_CRYPTO("sha1");
```
