# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_9
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_9`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 27-67 of the vulnerable file.


static int rxrpc_vet_description_s(const char *);
static int rxrpc_preparse(struct key_preparsed_payload *);
static int rxrpc_preparse_s(struct key_preparsed_payload *);
static void rxrpc_free_preparse(struct key_preparsed_payload *);
static void rxrpc_free_preparse_s(struct key_preparsed_payload *);
static void rxrpc_destroy(struct key *);
static void rxrpc_destroy_s(struct key *);
static void rxrpc_describe(const struct key *, struct seq_file *);
static long rxrpc_read(const struct key *, char __user *, size_t);

/*
 * rxrpc defined keys take an arbitrary string as the description and an
 * arbitrary blob of data as the payload
 */
struct key_type key_type_rxrpc = {
	.name		= "rxrpc",
	.preparse	= rxrpc_preparse,
	.free_preparse	= rxrpc_free_preparse,
	.instantiate	= generic_key_instantiate,
	.match		= user_match,
	.destroy	= rxrpc_destroy,
	.describe	= rxrpc_describe,
	.read		= rxrpc_read,
};
EXPORT_SYMBOL(key_type_rxrpc);

/*
 * rxrpc server defined keys take "<serviceId>:<securityIndex>" as the
 * description and an 8-byte decryption key as the payload
 */
struct key_type key_type_rxrpc_s = {
	.name		= "rxrpc_s",
	.vet_description = rxrpc_vet_description_s,
	.preparse	= rxrpc_preparse_s,
	.free_preparse	= rxrpc_free_preparse_s,
	.instantiate	= generic_key_instantiate,
	.match		= user_match,
	.destroy	= rxrpc_destroy_s,
	.describe	= rxrpc_describe,
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,7 +44,6 @@
 	.preparse	= rxrpc_preparse,
 	.free_preparse	= rxrpc_free_preparse,
 	.instantiate	= generic_key_instantiate,
-	.match		= user_match,
 	.destroy	= rxrpc_destroy,
 	.describe	= rxrpc_describe,
 	.read		= rxrpc_read,
@@ -61,7 +60,6 @@
 	.preparse	= rxrpc_preparse_s,
 	.free_preparse	= rxrpc_free_preparse_s,
 	.instantiate	= generic_key_instantiate,
-	.match		= user_match,
 	.destroy	= rxrpc_destroy_s,
 	.describe	= rxrpc_describe,
 };
```
