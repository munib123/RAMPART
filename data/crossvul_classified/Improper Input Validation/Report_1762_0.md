# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1762_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1762_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 117-158 of the vulnerable file.

	wait_on_bit(&key_gc_flags, KEY_GC_REAPING_KEYTYPE,
		    TASK_UNINTERRUPTIBLE);

	key_gc_dead_keytype = NULL;
	kleave("");
}

/*
 * Garbage collect a list of unreferenced, detached keys
 */
static noinline void key_gc_unused_keys(struct list_head *keys)
{
	while (!list_empty(keys)) {
		struct key *key =
			list_entry(keys->next, struct key, graveyard_link);
		list_del(&key->graveyard_link);

		kdebug("- %u", key->serial);
		key_check(key);

		/* Throw away the key data */
		if (key->type->destroy)
			key->type->destroy(key);

		security_key_free(key);

		/* deal with the user's key tracking and quota */
		if (test_bit(KEY_FLAG_IN_QUOTA, &key->flags)) {
			spin_lock(&key->user->lock);
			key->user->qnkeys--;
			key->user->qnbytes -= key->quotalen;
			spin_unlock(&key->user->lock);
		}

		atomic_dec(&key->user->nkeys);
		if (test_bit(KEY_FLAG_INSTANTIATED, &key->flags))
			atomic_dec(&key->user->nikeys);

		key_user_put(key->user);

		kfree(key->description);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,8 +134,10 @@
 		kdebug("- %u", key->serial);
 		key_check(key);
 
-		/* Throw away the key data */
-		if (key->type->destroy)
+		/* Throw away the key data if the key is instantiated */
+		if (test_bit(KEY_FLAG_INSTANTIATED, &key->flags) &&
+		    !test_bit(KEY_FLAG_NEGATIVE, &key->flags) &&
+		    key->type->destroy)
 			key->type->destroy(key);
 
 		security_key_free(key);
```
