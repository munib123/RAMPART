# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 3569_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3569_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 22-62 of the vulnerable file.

#include "xfs_inode.h"
#include "xfs_vnodeops.h"
#include "xfs_trace.h"
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>


/*
 * Locking scheme:
 *  - all ACL updates are protected by inode->i_mutex, which is taken before
 *    calling into this file.
 */

STATIC struct posix_acl *
xfs_acl_from_disk(struct xfs_acl *aclp)
{
	struct posix_acl_entry *acl_e;
	struct posix_acl *acl;
	struct xfs_acl_entry *ace;
	int count, i;

	count = be32_to_cpu(aclp->acl_cnt);
	if (count > XFS_ACL_MAX_ENTRIES)
		return ERR_PTR(-EFSCORRUPTED);

	acl = posix_acl_alloc(count, GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < count; i++) {
		acl_e = &acl->a_entries[i];
		ace = &aclp->acl_entry[i];

		/*
		 * The tag is 32 bits on disk and 16 bits in core.
		 *
		 * Because every access to it goes through the core
		 * format first this is not a problem.
		 */
		acl_e->e_tag = be32_to_cpu(ace->ae_tag);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
 	struct posix_acl_entry *acl_e;
 	struct posix_acl *acl;
 	struct xfs_acl_entry *ace;
-	int count, i;
+	unsigned int count, i;
 
 	count = be32_to_cpu(aclp->acl_cnt);
 	if (count > XFS_ACL_MAX_ENTRIES)
```
