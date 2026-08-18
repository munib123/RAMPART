# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5616_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5616_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1-32 of the vulnerable file.

/*
 *  linux/fs/pnode.c
 *
 * (C) Copyright IBM Corporation 2005.
 *	Released under GPL v2.
 *	Author : Ram Pai (linuxram@us.ibm.com)
 *
 */
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include "internal.h"
#include "pnode.h"

/* return the next shared peer mount of @p */
static inline struct mount *next_peer(struct mount *p)
{
	return list_entry(p->mnt_share.next, struct mount, mnt_share);
}

static inline struct mount *first_slave(struct mount *p)
{
	return list_entry(p->mnt_slave_list.next, struct mount, mnt_slave);
}

static inline struct mount *next_slave(struct mount *p)
{
	return list_entry(p->mnt_slave.next, struct mount, mnt_slave);
}

static struct mount *get_peer_under_root(struct mount *mnt,
					 struct mnt_namespace *ns,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
 #include <linux/mnt_namespace.h>
 #include <linux/mount.h>
 #include <linux/fs.h>
+#include <linux/nsproxy.h>
 #include "internal.h"
 #include "pnode.h"
 
@@ -220,6 +221,7 @@
 int propagate_mnt(struct mount *dest_mnt, struct dentry *dest_dentry,
 		    struct mount *source_mnt, struct list_head *tree_list)
 {
+	struct user_namespace *user_ns = current->nsproxy->mnt_ns->user_ns;
 	struct mount *m, *child;
 	int ret = 0;
 	struct mount *prev_dest_mnt = dest_mnt;
@@ -236,6 +238,10 @@
 			continue;
 
 		source =  get_source(m, prev_dest_mnt, prev_src_mnt, &type);
+
+		/* Notice when we are propagating across user namespaces */
+		if (m->mnt_ns->user_ns != user_ns)
+			type |= CL_UNPRIVILEGED;
 
 		child = copy_tree(source, source->mnt.mnt_root, type);
 		if (IS_ERR(child)) {
```
