# CrossVul Fix Pair: 7PK in c
**Pair ID:** 1547_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1547_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 541-581 of the vulnerable file.

}

static int __nd_alloc_stack(struct nameidata *nd)
{
	struct saved *p;

	if (nd->flags & LOOKUP_RCU) {
		p= kmalloc(MAXSYMLINKS * sizeof(struct saved),
				  GFP_ATOMIC);
		if (unlikely(!p))
			return -ECHILD;
	} else {
		p= kmalloc(MAXSYMLINKS * sizeof(struct saved),
				  GFP_KERNEL);
		if (unlikely(!p))
			return -ENOMEM;
	}
	memcpy(p, nd->internal, sizeof(nd->internal));
	nd->stack = p;
	return 0;
}

static inline int nd_alloc_stack(struct nameidata *nd)
{
	if (likely(nd->depth != EMBEDDED_LEVELS))
		return 0;
	if (likely(nd->stack != nd->internal))
		return 0;
	return __nd_alloc_stack(nd);
}

static void drop_links(struct nameidata *nd)
{
	int i = nd->depth;
	while (i--) {
		struct saved *last = nd->stack + i;
		struct inode *inode = last->inode;
		if (last->cookie && inode->i_op->put_link) {
			inode->i_op->put_link(inode, last->cookie);
			last->cookie = NULL;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -560,6 +560,24 @@
 	return 0;
 }
 
+/**
+ * path_connected - Verify that a path->dentry is below path->mnt.mnt_root
+ * @path: nameidate to verify
+ *
+ * Rename can sometimes move a file or directory outside of a bind
+ * mount, path_connected allows those cases to be detected.
+ */
+static bool path_connected(const struct path *path)
+{
+	struct vfsmount *mnt = path->mnt;
+
+	/* Only bind mounts can have disconnected paths */
+	if (mnt->mnt_root == mnt->mnt_sb->s_root)
+		return true;
+
+	return is_subdir(path->dentry, mnt->mnt_root);
+}
+
 static inline int nd_alloc_stack(struct nameidata *nd)
 {
 	if (likely(nd->depth != EMBEDDED_LEVELS))
@@ -1296,6 +1314,8 @@
 				return -ECHILD;
 			nd->path.dentry = parent;
 			nd->seq = seq;
+			if (unlikely(!path_connected(&nd->path)))
+				return -ENOENT;
 			break;
 		} else {
 			struct mount *mnt = real_mount(nd->path.mnt);
@@ -1396,7 +1416,7 @@
 	}
 }
 
-static void follow_dotdot(struct nameidata *nd)
+static int follow_dotdot(struct nameidata *nd)
 {
 	if (!nd->root.mnt)
 		set_root(nd);
@@ -1412,6 +1432,8 @@
 			/* rare case of legitimate dget_parent()... */
 			nd->path.dentry = dget_parent(nd->path.dentry);
 			dput(old);
+			if (unlikely(!path_connected(&nd->path)))
+				return -ENOENT;
 			break;
 		}
 		if (!follow_up(&nd->path))
@@ -1419,6 +1441,7 @@
 	}
 	follow_mount(&nd->path);
 	nd->inode = nd->path.dentry->d_inode;
+	return 0;
 }
 
 /*
@@ -1634,7 +1657,7 @@
 		if (nd->flags & LOOKUP_RCU) {
 			return follow_dotdot_rcu(nd);
 		} else
-			follow_dotdot(nd);
+			return follow_dotdot(nd);
 	}
 	return 0;
 }
```
