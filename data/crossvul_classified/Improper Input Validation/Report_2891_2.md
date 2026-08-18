# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2891_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2891_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 230-270 of the vulnerable file.

void big_key_free_preparse(struct key_preparsed_payload *prep)
{
	if (prep->datalen > BIG_KEY_FILE_THRESHOLD) {
		struct path *path = (struct path *)&prep->payload.data[big_key_path];

		path_put(path);
	}
	kzfree(prep->payload.data[big_key_data]);
}

/*
 * dispose of the links from a revoked keyring
 * - called with the key sem write-locked
 */
void big_key_revoke(struct key *key)
{
	struct path *path = (struct path *)&key->payload.data[big_key_path];

	/* clear the quota */
	key_payload_reserve(key, 0);
	if (key_is_instantiated(key) &&
	    (size_t)key->payload.data[big_key_len] > BIG_KEY_FILE_THRESHOLD)
		vfs_truncate(path, 0);
}

/*
 * dispose of the data dangling from the corpse of a big_key key
 */
void big_key_destroy(struct key *key)
{
	size_t datalen = (size_t)key->payload.data[big_key_len];

	if (datalen > BIG_KEY_FILE_THRESHOLD) {
		struct path *path = (struct path *)&key->payload.data[big_key_path];

		path_put(path);
		path->mnt = NULL;
		path->dentry = NULL;
	}
	kzfree(key->payload.data[big_key_data]);
	key->payload.data[big_key_data] = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -247,7 +247,7 @@
 
 	/* clear the quota */
 	key_payload_reserve(key, 0);
-	if (key_is_instantiated(key) &&
+	if (key_is_positive(key) &&
 	    (size_t)key->payload.data[big_key_len] > BIG_KEY_FILE_THRESHOLD)
 		vfs_truncate(path, 0);
 }
@@ -279,7 +279,7 @@
 
 	seq_puts(m, key->description);
 
-	if (key_is_instantiated(key))
+	if (key_is_positive(key))
 		seq_printf(m, ": %zu [%s]",
 			   datalen,
 			   datalen > BIG_KEY_FILE_THRESHOLD ? "file" : "buff");
```
