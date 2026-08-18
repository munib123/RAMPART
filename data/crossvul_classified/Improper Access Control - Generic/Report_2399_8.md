# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2399_8
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2399_8`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 938-957 of the vulnerable file.

		return err;

	err = crypto_register_template(&cryptd_tmpl);
	if (err)
		cryptd_fini_queue(&queue);

	return err;
}

static void __exit cryptd_exit(void)
{
	cryptd_fini_queue(&queue);
	crypto_unregister_template(&cryptd_tmpl);
}

subsys_initcall(cryptd_init);
module_exit(cryptd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Software async crypto daemon");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -955,3 +955,4 @@
 
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("Software async crypto daemon");
+MODULE_ALIAS_CRYPTO("cryptd");
```
