# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_7
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_7`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 459-489 of the vulnerable file.

static void ceph_key_free_preparse(struct key_preparsed_payload *prep)
{
	struct ceph_crypto_key *ckey = prep->payload[0];
	ceph_crypto_key_destroy(ckey);
	kfree(ckey);
}

static void ceph_key_destroy(struct key *key)
{
	struct ceph_crypto_key *ckey = key->payload.data;

	ceph_crypto_key_destroy(ckey);
	kfree(ckey);
}

struct key_type key_type_ceph = {
	.name		= "ceph",
	.preparse	= ceph_key_preparse,
	.free_preparse	= ceph_key_free_preparse,
	.instantiate	= generic_key_instantiate,
	.match		= user_match,
	.destroy	= ceph_key_destroy,
};

int ceph_crypto_init(void) {
	return register_key_type(&key_type_ceph);
}

void ceph_crypto_shutdown(void) {
	unregister_key_type(&key_type_ceph);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -476,7 +476,6 @@
 	.preparse	= ceph_key_preparse,
 	.free_preparse	= ceph_key_free_preparse,
 	.instantiate	= generic_key_instantiate,
-	.match		= user_match,
 	.destroy	= ceph_key_destroy,
 };
 
```
