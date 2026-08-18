# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5192_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5192_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 483-523 of the vulnerable file.

		profile = aa_get_newest_profile(cxt->previous);
	else if (strcmp(name, "exec") == 0 && cxt->onexec)
		profile = aa_get_newest_profile(cxt->onexec);
	else
		error = -EINVAL;

	if (profile)
		error = aa_getprocattr(profile, value);

	aa_put_profile(profile);
	put_cred(cred);

	return error;
}

static int apparmor_setprocattr(struct task_struct *task, char *name,
				void *value, size_t size)
{
	struct common_audit_data sa;
	struct apparmor_audit_data aad = {0,};
	char *command, *args = value;
	size_t arg_size;
	int error;

	if (size == 0)
		return -EINVAL;
	/* args points to a PAGE_SIZE buffer, AppArmor requires that
	 * the buffer must be null terminated or have size <= PAGE_SIZE -1
	 * so that AppArmor can null terminate them
	 */
	if (args[size - 1] != '\0') {
		if (size == PAGE_SIZE)
			return -EINVAL;
		args[size] = '\0';
	}

	/* task can only write its own attributes */
	if (current != task)
		return -EACCES;

	args = value;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -500,34 +500,34 @@
 {
 	struct common_audit_data sa;
 	struct apparmor_audit_data aad = {0,};
-	char *command, *args = value;
+	char *command, *largs = NULL, *args = value;
 	size_t arg_size;
 	int error;
 
 	if (size == 0)
 		return -EINVAL;
-	/* args points to a PAGE_SIZE buffer, AppArmor requires that
-	 * the buffer must be null terminated or have size <= PAGE_SIZE -1
-	 * so that AppArmor can null terminate them
-	 */
-	if (args[size - 1] != '\0') {
-		if (size == PAGE_SIZE)
-			return -EINVAL;
-		args[size] = '\0';
-	}
-
 	/* task can only write its own attributes */
 	if (current != task)
 		return -EACCES;
 
-	args = value;
+	/* AppArmor requires that the buffer must be null terminated atm */
+	if (args[size - 1] != '\0') {
+		/* null terminate */
+		largs = args = kmalloc(size + 1, GFP_KERNEL);
+		if (!args)
+			return -ENOMEM;
+		memcpy(args, value, size);
+		args[size] = '\0';
+	}
+
+	error = -EINVAL;
 	args = strim(args);
 	command = strsep(&args, " ");
 	if (!args)
-		return -EINVAL;
+		goto out;
 	args = skip_spaces(args);
 	if (!*args)
-		return -EINVAL;
+		goto out;
 
 	arg_size = size - (args - (char *) value);
 	if (strcmp(name, "current") == 0) {
@@ -553,10 +553,12 @@
 			goto fail;
 	} else
 		/* only support the "current" and "exec" process attributes */
-		return -EINVAL;
+		goto fail;
 
 	if (!error)
 		error = size;
+out:
+	kfree(largs);
 	return error;
 
 fail:
@@ -565,9 +567,9 @@
 	aad.profile = aa_current_profile();
 	aad.op = OP_SETPROCATTR;
 	aad.info = name;
-	aad.error = -EINVAL;
+	aad.error = error = -EINVAL;
 	aa_audit_msg(AUDIT_APPARMOR_DENIED, &sa, NULL);
-	return -EINVAL;
+	goto out;
 }
 
 static int apparmor_task_setrlimit(struct task_struct *task,
```
