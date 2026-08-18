# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2891_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2891_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 749-792 of the vulnerable file.

 *
 * If successful, we place up to buflen bytes of data into the buffer, if one
 * is provided, and return the amount of data that is available in the key,
 * irrespective of how much we copied into the buffer.
 */
long keyctl_read_key(key_serial_t keyid, char __user *buffer, size_t buflen)
{
	struct key *key;
	key_ref_t key_ref;
	long ret;

	/* find the key first */
	key_ref = lookup_user_key(keyid, 0, 0);
	if (IS_ERR(key_ref)) {
		ret = -ENOKEY;
		goto error;
	}

	key = key_ref_to_ptr(key_ref);

	if (test_bit(KEY_FLAG_NEGATIVE, &key->flags)) {
		ret = -ENOKEY;
		goto error2;
	}

	/* see if we can read it directly */
	ret = key_permission(key_ref, KEY_NEED_READ);
	if (ret == 0)
		goto can_read_key;
	if (ret != -EACCES)
		goto error2;

	/* we can't; see if it's searchable from this process's keyrings
	 * - we automatically take account of the fact that it may be
	 *   dangling off an instantiation key
	 */
	if (!is_key_possessed(key_ref)) {
		ret = -EACCES;
		goto error2;
	}

	/* the key is probably readable - now try to read it */
can_read_key:
	ret = -EOPNOTSUPP;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -766,10 +766,9 @@
 
 	key = key_ref_to_ptr(key_ref);
 
-	if (test_bit(KEY_FLAG_NEGATIVE, &key->flags)) {
-		ret = -ENOKEY;
-		goto error2;
-	}
+	ret = key_read_state(key);
+	if (ret < 0)
+		goto error2; /* Negatively instantiated */
 
 	/* see if we can read it directly */
 	ret = key_permission(key_ref, KEY_NEED_READ);
@@ -901,7 +900,7 @@
 		atomic_dec(&key->user->nkeys);
 		atomic_inc(&newowner->nkeys);
 
-		if (test_bit(KEY_FLAG_INSTANTIATED, &key->flags)) {
+		if (key->state != KEY_IS_UNINSTANTIATED) {
 			atomic_dec(&key->user->nikeys);
 			atomic_inc(&newowner->nikeys);
 		}
```
