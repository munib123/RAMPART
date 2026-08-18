# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2891_9
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2891_9`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 713-753 of the vulnerable file.


	if (!(lflags & KEY_LOOKUP_PARTIAL)) {
		ret = wait_for_key_construction(key, true);
		switch (ret) {
		case -ERESTARTSYS:
			goto invalid_key;
		default:
			if (perm)
				goto invalid_key;
		case 0:
			break;
		}
	} else if (perm) {
		ret = key_validate(key);
		if (ret < 0)
			goto invalid_key;
	}

	ret = -EIO;
	if (!(lflags & KEY_LOOKUP_PARTIAL) &&
	    !test_bit(KEY_FLAG_INSTANTIATED, &key->flags))
		goto invalid_key;

	/* check the permissions */
	ret = key_task_permission(key_ref, ctx.cred, perm);
	if (ret < 0)
		goto invalid_key;

	key->last_used_at = current_kernel_time().tv_sec;

error:
	put_cred(ctx.cred);
	return key_ref;

invalid_key:
	key_ref_put(key_ref);
	key_ref = ERR_PTR(ret);
	goto error;

	/* if we attempted to install a keyring, then it may have caused new
	 * creds to be installed */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -730,7 +730,7 @@
 
 	ret = -EIO;
 	if (!(lflags & KEY_LOOKUP_PARTIAL) &&
-	    !test_bit(KEY_FLAG_INSTANTIATED, &key->flags))
+	    key_read_state(key) == KEY_IS_UNINSTANTIATED)
 		goto invalid_key;
 
 	/* check the permissions */
```
