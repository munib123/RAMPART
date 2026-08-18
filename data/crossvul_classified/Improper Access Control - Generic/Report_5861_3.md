# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5861_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5861_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 284-305 of the vulnerable file.


static int __init sha512_neon_mod_init(void)
{
	if (!cpu_has_neon())
		return -ENODEV;

	return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}

static void __exit sha512_neon_mod_fini(void)
{
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

module_init(sha512_neon_mod_init);
module_exit(sha512_neon_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA512 Secure Hash Algorithm, NEON accelerated");

MODULE_ALIAS("sha512");
MODULE_ALIAS("sha384");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -301,5 +301,5 @@
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("SHA512 Secure Hash Algorithm, NEON accelerated");
 
-MODULE_ALIAS("sha512");
-MODULE_ALIAS("sha384");
+MODULE_ALIAS_CRYPTO("sha512");
+MODULE_ALIAS_CRYPTO("sha384");
```
