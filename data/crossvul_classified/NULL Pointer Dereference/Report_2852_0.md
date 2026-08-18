# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2852_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2852_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 82-122 of the vulnerable file.

	description = NULL;
	if (_description) {
		description = strndup_user(_description, KEY_MAX_DESC_SIZE);
		if (IS_ERR(description)) {
			ret = PTR_ERR(description);
			goto error;
		}
		if (!*description) {
			kfree(description);
			description = NULL;
		} else if ((description[0] == '.') &&
			   (strncmp(type, "keyring", 7) == 0)) {
			ret = -EPERM;
			goto error2;
		}
	}

	/* pull the payload in if one was supplied */
	payload = NULL;

	if (_payload) {
		ret = -ENOMEM;
		payload = kvmalloc(plen, GFP_KERNEL);
		if (!payload)
			goto error2;

		ret = -EFAULT;
		if (copy_from_user(payload, _payload, plen) != 0)
			goto error3;
	}

	/* find the target keyring (which must be writable) */
	keyring_ref = lookup_user_key(ringid, KEY_LOOKUP_CREATE, KEY_NEED_WRITE);
	if (IS_ERR(keyring_ref)) {
		ret = PTR_ERR(keyring_ref);
		goto error3;
	}

	/* create or update the requested key and add it to the target
	 * keyring */
	key_ref = key_create_or_update(keyring_ref, type, description,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,7 @@
 	/* pull the payload in if one was supplied */
 	payload = NULL;
 
-	if (_payload) {
+	if (plen) {
 		ret = -ENOMEM;
 		payload = kvmalloc(plen, GFP_KERNEL);
 		if (!payload)
@@ -324,7 +324,7 @@
 
 	/* pull the payload in if one was supplied */
 	payload = NULL;
-	if (_payload) {
+	if (plen) {
 		ret = -ENOMEM;
 		payload = kmalloc(plen, GFP_KERNEL);
 		if (!payload)
```
