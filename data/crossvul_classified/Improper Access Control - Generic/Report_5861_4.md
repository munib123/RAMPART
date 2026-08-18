# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5861_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5861_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 277-297 of the vulnerable file.

};

static int __init aes_mod_init(void)
{
	if (!(elf_hwcap & HWCAP_AES))
		return -ENODEV;
	return crypto_register_alg(&ccm_aes_alg);
}

static void __exit aes_mod_exit(void)
{
	crypto_unregister_alg(&ccm_aes_alg);
}

module_init(aes_mod_init);
module_exit(aes_mod_exit);

MODULE_DESCRIPTION("Synchronous AES in CCM mode using ARMv8 Crypto Extensions");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("ccm(aes)");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -294,4 +294,4 @@
 MODULE_DESCRIPTION("Synchronous AES in CCM mode using ARMv8 Crypto Extensions");
 MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
 MODULE_LICENSE("GPL v2");
-MODULE_ALIAS("ccm(aes)");
+MODULE_ALIAS_CRYPTO("ccm(aes)");
```
