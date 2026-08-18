# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5592_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5592_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 40-80 of the vulnerable file.

/*
 * Install the user and user session keyrings for the current process's UID.
 */
int install_user_keyrings(void)
{
	struct user_struct *user;
	const struct cred *cred;
	struct key *uid_keyring, *session_keyring;
	key_perm_t user_keyring_perm;
	char buf[20];
	int ret;
	uid_t uid;

	user_keyring_perm = (KEY_POS_ALL & ~KEY_POS_SETATTR) | KEY_USR_ALL;
	cred = current_cred();
	user = cred->user;
	uid = from_kuid(cred->user_ns, user->uid);

	kenter("%p{%u}", user, uid);

	if (user->uid_keyring) {
		kleave(" = 0 [exist]");
		return 0;
	}

	mutex_lock(&key_user_keyring_mutex);
	ret = 0;

	if (!user->uid_keyring) {
		/* get the UID-specific keyring
		 * - there may be one in existence already as it may have been
		 *   pinned by a session, but the user_struct pointing to it
		 *   may have been destroyed by setuid */
		sprintf(buf, "_uid.%u", uid);

		uid_keyring = find_keyring_by_name(buf, true);
		if (IS_ERR(uid_keyring)) {
			uid_keyring = keyring_alloc(buf, user->uid, INVALID_GID,
						    cred, user_keyring_perm,
						    KEY_ALLOC_IN_QUOTA, NULL);
			if (IS_ERR(uid_keyring)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,7 +57,7 @@
 
 	kenter("%p{%u}", user, uid);
 
-	if (user->uid_keyring) {
+	if (user->uid_keyring && user->session_keyring) {
 		kleave(" = 0 [exist]");
 		return 0;
 	}
```
