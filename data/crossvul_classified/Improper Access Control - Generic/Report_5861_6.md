# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5861_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5861_6`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 137-157 of the vulnerable file.

		.cra_module	=	THIS_MODULE,
	}
};

static int __init sha1_powerpc_mod_init(void)
{
	return crypto_register_shash(&alg);
}

static void __exit sha1_powerpc_mod_fini(void)
{
	crypto_unregister_shash(&alg);
}

module_init(sha1_powerpc_mod_init);
module_exit(sha1_powerpc_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA1 Secure Hash Algorithm");

MODULE_ALIAS("sha1-powerpc");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -154,4 +154,4 @@
 MODULE_LICENSE("GPL");
 MODULE_DESCRIPTION("SHA1 Secure Hash Algorithm");
 
-MODULE_ALIAS("sha1-powerpc");
+MODULE_ALIAS_CRYPTO("sha1-powerpc");
```
