# CrossVul Fix Pair: Improper Privilege Management in javascript
**Pair ID:** 4115_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4115_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```javascript
Lines 263-303 of the vulnerable file.

	async function updateFullname(uid, newFullname) {
		const fullname = await User.getUserField(uid, 'fullname');
		await updateUidMapping('fullname', uid, newFullname, fullname);
	}

	User.changePassword = async function (uid, data) {
		if (uid <= 0 || !data || !data.uid) {
			throw new Error('[[error:invalid-uid]]');
		}
		User.isPasswordValid(data.newPassword);
		const [isAdmin, hasPassword] = await Promise.all([
			User.isAdministrator(uid),
			User.hasPassword(uid),
		]);

		if (meta.config['password:disableEdit'] && !isAdmin) {
			throw new Error('[[error:no-privileges]]');
		}
		let isAdminOrPasswordMatch = false;
		const isSelf = parseInt(uid, 10) === parseInt(data.uid, 10);
		if (
			(isAdmin && !isSelf) || // Admins ok
			(!hasPassword && isSelf)	// Initial password set ok
		) {
			isAdminOrPasswordMatch = true;
		} else {
			isAdminOrPasswordMatch = await User.isPasswordCorrect(uid, data.currentPassword, data.ip);
		}

		if (!isAdminOrPasswordMatch) {
			throw new Error('[[user:change_password_error_wrong_current]]');
		}

		const hashedPassword = await User.hashPassword(data.newPassword);
		await Promise.all([
			User.setUserFields(data.uid, {
				password: hashedPassword,
				rss_token: utils.generateUUID(),
			}),
			User.reset.updateExpiry(data.uid),
			User.auth.revokeAllSessions(data.uid),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -280,13 +280,18 @@
 		}
 		let isAdminOrPasswordMatch = false;
 		const isSelf = parseInt(uid, 10) === parseInt(data.uid, 10);
+
+		if (!isAdmin && !isSelf) {
+			throw new Error('[[user:change_password_error_privileges]]');
+		}
+
 		if (
 			(isAdmin && !isSelf) || // Admins ok
 			(!hasPassword && isSelf)	// Initial password set ok
 		) {
 			isAdminOrPasswordMatch = true;
 		} else {
-			isAdminOrPasswordMatch = await User.isPasswordCorrect(uid, data.currentPassword, data.ip);
+			isAdminOrPasswordMatch = await User.isPasswordCorrect(data.uid, data.currentPassword, data.ip);
 		}
 
 		if (!isAdminOrPasswordMatch) {
```
