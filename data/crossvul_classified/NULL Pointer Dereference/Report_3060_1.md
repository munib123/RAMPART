# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 58-98 of the vulnerable file.

	ret = user_preparse(prep);
	prep->data = saved_prep_data;
	prep->datalen = saved_prep_datalen;

error_free:
	pkcs7_free_message(pkcs7);
error:
	kleave(" = %d", ret);
	return ret;
}

/*
 * user defined keys take an arbitrary string as the description and an
 * arbitrary blob of data as the payload
 */
static struct key_type key_type_pkcs7 = {
	.name			= "pkcs7_test",
	.preparse		= pkcs7_preparse,
	.free_preparse		= user_free_preparse,
	.instantiate		= generic_key_instantiate,
	.match			= user_match,
	.revoke			= user_revoke,
	.destroy		= user_destroy,
	.describe		= user_describe,
	.read			= user_read,
};

/*
 * Module stuff
 */
static int __init pkcs7_key_init(void)
{
	return register_key_type(&key_type_pkcs7);
}

static void __exit pkcs7_key_cleanup(void)
{
	unregister_key_type(&key_type_pkcs7);
}

module_init(pkcs7_key_init);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,6 @@
 	.preparse		= pkcs7_preparse,
 	.free_preparse		= user_free_preparse,
 	.instantiate		= generic_key_instantiate,
-	.match			= user_match,
 	.revoke			= user_revoke,
 	.destroy		= user_destroy,
 	.describe		= user_describe,
```
