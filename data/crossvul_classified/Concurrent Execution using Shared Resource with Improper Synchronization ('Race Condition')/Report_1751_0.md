# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 1751_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1751_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 734-780 of the vulnerable file.

	key = key_ref_to_ptr(key_ref);

	/* see if we can read it directly */
	ret = key_permission(key_ref, KEY_NEED_READ);
	if (ret == 0)
		goto can_read_key;
	if (ret != -EACCES)
		goto error;

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
	ret = key_validate(key);
	if (ret == 0) {
		ret = -EOPNOTSUPP;
		if (key->type->read) {
			/* read the data with the semaphore held (since we
			 * might sleep) */
			down_read(&key->sem);
			ret = key->type->read(key, buffer, buflen);
			up_read(&key->sem);
		}
	}

error2:
	key_put(key);
error:
	return ret;
}

/*
 * Change the ownership of a key
 *
 * The key must grant the caller Setattr permission for this to work, though
 * the key need not be fully instantiated yet.  For the UID to be changed, or
 * for the GID to be changed to a group the caller is not a member of, the
 * caller must have sysadmin capability.  If either uid or gid is -1 then that
 * attribute is not changed.
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -751,16 +751,16 @@
 
 	/* the key is probably readable - now try to read it */
 can_read_key:
-	ret = key_validate(key);
-	if (ret == 0) {
-		ret = -EOPNOTSUPP;
-		if (key->type->read) {
-			/* read the data with the semaphore held (since we
-			 * might sleep) */
-			down_read(&key->sem);
+	ret = -EOPNOTSUPP;
+	if (key->type->read) {
+		/* Read the data with the semaphore held (since we might sleep)
+		 * to protect against the key being updated or revoked.
+		 */
+		down_read(&key->sem);
+		ret = key_validate(key);
+		if (ret == 0)
 			ret = key->type->read(key, buffer, buflen);
-			up_read(&key->sem);
-		}
+		up_read(&key->sem);
 	}
 
 error2:
```
