# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5605_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5605_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 4-44 of the vulnerable file.

 *  published by the Free Software Foundation, version 2 of the
 *  License.
 */

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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,6 +21,7 @@
 #include <linux/uaccess.h>
 #include <linux/ctype.h>
 #include <linux/projid.h>
+#include <linux/fs_struct.h>
 
 static struct kmem_cache *user_ns_cachep __read_mostly;
 
@@ -837,6 +838,9 @@
 	if (atomic_read(&current->mm->mm_users) > 1)
 		return -EINVAL;
 
+	if (current->fs->users != 1)
+		return -EINVAL;
+
 	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
 		return -EPERM;
 
```
