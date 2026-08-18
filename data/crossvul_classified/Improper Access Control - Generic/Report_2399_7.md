# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2399_7
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2399_7`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 296-315 of the vulnerable file.

	.create = cmac_create,
	.free = shash_free_instance,
	.module = THIS_MODULE,
};

static int __init crypto_cmac_module_init(void)
{
	return crypto_register_template(&crypto_cmac_tmpl);
}

static void __exit crypto_cmac_module_exit(void)
{
	crypto_unregister_template(&crypto_cmac_tmpl);
}

module_init(crypto_cmac_module_init);
module_exit(crypto_cmac_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CMAC keyed hash algorithm");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -313,3 +313,4 @@
 
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("CMAC keyed hash algorithm");
+MODULE_ALIAS_CRYPTO("cmac");
```
