# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2605_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2605_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 748-788 of the vulnerable file.

 * caller Search permission when searched for from the process keyrings.
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
	if (key->type->read) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -766,6 +766,11 @@
 
 	key = key_ref_to_ptr(key_ref);
 
+	if (test_bit(KEY_FLAG_NEGATIVE, &key->flags)) {
+		ret = -ENOKEY;
+		goto error2;
+	}
+
 	/* see if we can read it directly */
 	ret = key_permission(key_ref, KEY_NEED_READ);
 	if (ret == 0)
```
