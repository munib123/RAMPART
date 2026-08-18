# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5725_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5725_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 88-128 of the vulnerable file.

		kmem_cache_free(user_ns_cachep, ns);
		return ret;
	}

	atomic_set(&ns->count, 1);
	/* Leave the new->user_ns reference with the new user namespace. */
	ns->parent = parent_ns;
	ns->owner = owner;
	ns->group = group;

	set_cred_user_ns(new, ns);

	update_mnt_policy(ns);

	return 0;
}

int unshare_userns(unsigned long unshare_flags, struct cred **new_cred)
{
	struct cred *cred;

	if (!(unshare_flags & CLONE_NEWUSER))
		return 0;

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	*new_cred = cred;
	return create_user_ns(cred);
}

void free_user_ns(struct user_namespace *ns)
{
	struct user_namespace *parent;

	do {
		parent = ns->parent;
		proc_free_inum(ns->proc_inum);
		kmem_cache_free(user_ns_cachep, ns);
		ns = parent;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,16 +105,21 @@
 int unshare_userns(unsigned long unshare_flags, struct cred **new_cred)
 {
 	struct cred *cred;
+	int err = -ENOMEM;
 
 	if (!(unshare_flags & CLONE_NEWUSER))
 		return 0;
 
 	cred = prepare_creds();
-	if (!cred)
-		return -ENOMEM;
-
-	*new_cred = cred;
-	return create_user_ns(cred);
+	if (cred) {
+		err = create_user_ns(cred);
+		if (err)
+			put_cred(cred);
+		else
+			*new_cred = cred;
+	}
+
+	return err;
 }
 
 void free_user_ns(struct user_namespace *ns)
```
