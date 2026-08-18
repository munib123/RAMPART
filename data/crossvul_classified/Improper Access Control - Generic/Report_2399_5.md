# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2399_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2399_5`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 864-883 of the vulnerable file.

	crypto_unregister_template(&crypto_ccm_tmpl);
out_undo_base:
	crypto_unregister_template(&crypto_ccm_base_tmpl);
	goto out;
}

static void __exit crypto_ccm_module_exit(void)
{
	crypto_unregister_template(&crypto_rfc4309_tmpl);
	crypto_unregister_template(&crypto_ccm_tmpl);
	crypto_unregister_template(&crypto_ccm_base_tmpl);
}

module_init(crypto_ccm_module_init);
module_exit(crypto_ccm_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Counter with CBC MAC");
MODULE_ALIAS_CRYPTO("ccm_base");
MODULE_ALIAS_CRYPTO("rfc4309");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -881,3 +881,4 @@
 MODULE_DESCRIPTION("Counter with CBC MAC");
 MODULE_ALIAS_CRYPTO("ccm_base");
 MODULE_ALIAS_CRYPTO("rfc4309");
+MODULE_ALIAS_CRYPTO("ccm");
```
