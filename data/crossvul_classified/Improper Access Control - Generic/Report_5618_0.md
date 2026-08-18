# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5618_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5618_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/proc_fs.h>
#include <linux/highuid.h>
#include <linux/cred.h>
#include <linux/securebits.h>
#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/projid.h>
#include <linux/fs_struct.h>

static struct kmem_cache *user_ns_cachep __read_mostly;

static bool new_idmap_permitted(struct user_namespace *ns, int cap_setid,
				struct uid_gid_map *map);

static void set_cred_user_ns(struct cred *cred, struct user_namespace *user_ns)
{
	/* Start with the same capabilities as init but useless for doing
	 * anything as the capabilities are bound to the new user namespace.
	 */
	cred->securebits = SECUREBITS_DEFAULT;
	cred->cap_inheritable = CAP_EMPTY_SET;
	cred->cap_permitted = CAP_FULL_SET;
	cred->cap_effective = CAP_FULL_SET;
	cred->cap_bset = CAP_FULL_SET;
#ifdef CONFIG_KEYS
	key_put(cred->request_key_auth);
	cred->request_key_auth = NULL;
#endif
	/* tgcred will be cleared in our caller bc CLONE_THREAD won't be set */
	cred->user_ns = user_ns;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,8 @@
 
 static struct kmem_cache *user_ns_cachep __read_mostly;
 
-static bool new_idmap_permitted(struct user_namespace *ns, int cap_setid,
+static bool new_idmap_permitted(const struct file *file,
+				struct user_namespace *ns, int cap_setid,
 				struct uid_gid_map *map);
 
 static void set_cred_user_ns(struct cred *cred, struct user_namespace *user_ns)
@@ -700,7 +701,7 @@
 
 	ret = -EPERM;
 	/* Validate the user is allowed to use user id's mapped to. */
-	if (!new_idmap_permitted(ns, cap_setid, &new_map))
+	if (!new_idmap_permitted(file, ns, cap_setid, &new_map))
 		goto out;
 
 	/* Map the lower ids from the parent user namespace to the
@@ -787,7 +788,8 @@
 			 &ns->projid_map, &ns->parent->projid_map);
 }
 
-static bool new_idmap_permitted(struct user_namespace *ns, int cap_setid,
+static bool new_idmap_permitted(const struct file *file, 
+				struct user_namespace *ns, int cap_setid,
 				struct uid_gid_map *new_map)
 {
 	/* Allow mapping to your own filesystem ids */
@@ -811,8 +813,10 @@
 
 	/* Allow the specified ids if we have the appropriate capability
 	 * (CAP_SETUID or CAP_SETGID) over the parent user namespace.
+	 * And the opener of the id file also had the approprpiate capability.
 	 */
-	if (ns_capable(ns->parent, cap_setid))
+	if (ns_capable(ns->parent, cap_setid) &&
+	    file_ns_capable(file, ns->parent, cap_setid))
 		return true;
 
 	return false;
```
