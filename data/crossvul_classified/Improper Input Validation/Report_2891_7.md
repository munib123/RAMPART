# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2891_7
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2891_7`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 397-437 of the vulnerable file.

	if (keyring->restrict_link) {
		struct key_restriction *keyres = keyring->restrict_link;

		key_put(keyres->key);
		kfree(keyres);
	}

	assoc_array_destroy(&keyring->keys, &keyring_assoc_array_ops);
}

/*
 * Describe a keyring for /proc.
 */
static void keyring_describe(const struct key *keyring, struct seq_file *m)
{
	if (keyring->description)
		seq_puts(m, keyring->description);
	else
		seq_puts(m, "[anon]");

	if (key_is_instantiated(keyring)) {
		if (keyring->keys.nr_leaves_on_tree != 0)
			seq_printf(m, ": %lu", keyring->keys.nr_leaves_on_tree);
		else
			seq_puts(m, ": empty");
	}
}

struct keyring_read_iterator_context {
	size_t			buflen;
	size_t			count;
	key_serial_t __user	*buffer;
};

static int keyring_read_iterator(const void *object, void *data)
{
	struct keyring_read_iterator_context *ctx = data;
	const struct key *key = keyring_ptr_to_key(object);
	int ret;

	kenter("{%s,%d},,{%zu/%zu}",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -414,7 +414,7 @@
 	else
 		seq_puts(m, "[anon]");
 
-	if (key_is_instantiated(keyring)) {
+	if (key_is_positive(keyring)) {
 		if (keyring->keys.nr_leaves_on_tree != 0)
 			seq_printf(m, ": %lu", keyring->keys.nr_leaves_on_tree);
 		else
@@ -553,7 +553,8 @@
 {
 	struct keyring_search_context *ctx = iterator_data;
 	const struct key *key = keyring_ptr_to_key(object);
-	unsigned long kflags = key->flags;
+	unsigned long kflags = READ_ONCE(key->flags);
+	short state = READ_ONCE(key->state);
 
 	kenter("{%d}", key->serial);
 
@@ -597,9 +598,8 @@
 
 	if (ctx->flags & KEYRING_SEARCH_DO_STATE_CHECK) {
 		/* we set a different error code if we pass a negative key */
-		if (kflags & (1 << KEY_FLAG_NEGATIVE)) {
-			smp_rmb();
-			ctx->result = ERR_PTR(key->reject_error);
+		if (state < 0) {
+			ctx->result = ERR_PTR(state);
 			kleave(" = %d [neg]", ctx->skipped_ret);
 			goto skipped;
 		}
```
