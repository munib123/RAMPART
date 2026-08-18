# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3267_1
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3267_1`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 111-152 of the vulnerable file.

		/* install the keyrings */
		user->uid_keyring = uid_keyring;
		user->session_keyring = session_keyring;
	}

	mutex_unlock(&key_user_keyring_mutex);
	kleave(" = 0");
	return 0;

error_release_both:
	key_put(session_keyring);
error_release:
	key_put(uid_keyring);
error:
	mutex_unlock(&key_user_keyring_mutex);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Install a fresh thread keyring directly to new credentials.  This keyring is
 * allowed to overrun the quota.
 */
int install_thread_keyring_to_cred(struct cred *new)
{
	struct key *keyring;

	keyring = keyring_alloc("_tid", new->uid, new->gid, new,
				KEY_POS_ALL | KEY_USR_VIEW,
				KEY_ALLOC_QUOTA_OVERRUN,
				NULL, NULL);
	if (IS_ERR(keyring))
		return PTR_ERR(keyring);

	new->thread_keyring = keyring;
	return 0;
}

/*
 * Install a fresh thread keyring, discarding the old one.
 */
static int install_thread_keyring(void)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -128,12 +128,17 @@
 }
 
 /*
- * Install a fresh thread keyring directly to new credentials.  This keyring is
- * allowed to overrun the quota.
+ * Install a thread keyring to the given credentials struct if it didn't have
+ * one already.  This is allowed to overrun the quota.
+ *
+ * Return: 0 if a thread keyring is now present; -errno on failure.
  */
 int install_thread_keyring_to_cred(struct cred *new)
 {
 	struct key *keyring;
+
+	if (new->thread_keyring)
+		return 0;
 
 	keyring = keyring_alloc("_tid", new->uid, new->gid, new,
 				KEY_POS_ALL | KEY_USR_VIEW,
@@ -147,7 +152,9 @@
 }
 
 /*
- * Install a fresh thread keyring, discarding the old one.
+ * Install a thread keyring to the current task if it didn't have one already.
+ *
+ * Return: 0 if a thread keyring is now present; -errno on failure.
  */
 static int install_thread_keyring(void)
 {
@@ -157,8 +164,6 @@
 	new = prepare_creds();
 	if (!new)
 		return -ENOMEM;
-
-	BUG_ON(new->thread_keyring);
 
 	ret = install_thread_keyring_to_cred(new);
 	if (ret < 0) {
@@ -170,17 +175,17 @@
 }
 
 /*
- * Install a process keyring directly to a credentials struct.
- *
- * Returns -EEXIST if there was already a process keyring, 0 if one installed,
- * and other value on any other error
+ * Install a process keyring to the given credentials struct if it didn't have
+ * one already.  This is allowed to overrun the quota.
+ *
+ * Return: 0 if a process keyring is now present; -errno on failure.
  */
 int install_process_keyring_to_cred(struct cred *new)
 {
 	struct key *keyring;
 
 	if (new->process_keyring)
-		return -EEXIST;
+		return 0;
 
 	keyring = keyring_alloc("_pid", new->uid, new->gid, new,
 				KEY_POS_ALL | KEY_USR_VIEW,
@@ -194,11 +199,9 @@
 }
 
 /*
- * Make sure a process keyring is installed for the current process.  The
- * existing process keyring is not replaced.
- *
- * Returns 0 if there is a process keyring by the end of this function, some
- * error otherwise.
+ * Install a process keyring to the current task if it didn't have one already.
+ *
+ * Return: 0 if a process keyring is now present; -errno on failure.
  */
 static int install_process_keyring(void)
 {
@@ -212,14 +215,18 @@
 	ret = install_process_keyring_to_cred(new);
 	if (ret < 0) {
 		abort_creds(new);
-		return ret != -EEXIST ? ret : 0;
+		return ret;
 	}
 
 	return commit_creds(new);
 }
 
 /*
- * Install a session keyring directly to a credentials struct.
+ * Install the given keyring as the session keyring of the given credentials
+ * struct, replacing the existing one if any.  If the given keyring is NULL,
+ * then install a new anonymous session keyring.
+ *
+ * Return: 0 on success; -errno on failure.
  */
 int install_session_keyring_to_cred(struct cred *cred, struct key *keyring)
 {
@@ -254,8 +261,11 @@
 }
 
 /*
- * Install a session keyring, discarding the old one.  If a keyring is not
- * supplied, an empty one is invented.
+ * Install the given keyring as the session keyring of the current task,
+ * replacing the existing one if any.  If the given keyring is NULL, then
+ * install a new anonymous session keyring.
+ *
+ * Return: 0 on success; -errno on failure.
  */
 static int install_session_keyring(struct key *keyring)
 {
```
