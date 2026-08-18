# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3267_0
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3267_0`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 1241-1282 of the vulnerable file.


	/* instantiate the key and link it into a keyring */
	ret = key_reject_and_link(rka->target_key, timeout, error,
				  dest_keyring, instkey);

	key_put(dest_keyring);

	/* discard the assumed authority if it's just been disabled by
	 * instantiation of the key */
	if (ret == 0)
		keyctl_change_reqkey_auth(NULL);

error:
	return ret;
}

/*
 * Read or set the default keyring in which request_key() will cache keys and
 * return the old setting.
 *
 * If a process keyring is specified then this will be created if it doesn't
 * yet exist.  The old setting will be returned if successful.
 */
long keyctl_set_reqkey_keyring(int reqkey_defl)
{
	struct cred *new;
	int ret, old_setting;

	old_setting = current_cred_xxx(jit_keyring);

	if (reqkey_defl == KEY_REQKEY_DEFL_NO_CHANGE)
		return old_setting;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	switch (reqkey_defl) {
	case KEY_REQKEY_DEFL_THREAD_KEYRING:
		ret = install_thread_keyring_to_cred(new);
		if (ret < 0)
			goto error;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1258,8 +1258,8 @@
  * Read or set the default keyring in which request_key() will cache keys and
  * return the old setting.
  *
- * If a process keyring is specified then this will be created if it doesn't
- * yet exist.  The old setting will be returned if successful.
+ * If a thread or process keyring is specified then it will be created if it
+ * doesn't yet exist.  The old setting will be returned if successful.
  */
 long keyctl_set_reqkey_keyring(int reqkey_defl)
 {
@@ -1284,11 +1284,8 @@
 
 	case KEY_REQKEY_DEFL_PROCESS_KEYRING:
 		ret = install_process_keyring_to_cred(new);
-		if (ret < 0) {
-			if (ret != -EEXIST)
-				goto error;
-			ret = 0;
-		}
+		if (ret < 0)
+			goto error;
 		goto set;
 
 	case KEY_REQKEY_DEFL_DEFAULT:
```
