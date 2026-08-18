# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2406_3
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2406_3`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.

 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/posix_acl_xattr.h>
#include "ctree.h"
#include "btrfs_inode.h"
#include "transaction.h"
#include "xattr.h"
#include "disk-io.h"
#include "props.h"


ssize_t __btrfs_getxattr(struct inode *inode, const char *name,
				void *buffer, size_t size)
{
	struct btrfs_dir_item *di;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	int ret = 0;
	unsigned long data_ptr;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	/* lookup the xattr by name */
	di = btrfs_lookup_xattr(NULL, root, path, btrfs_ino(inode), name,
				strlen(name), 0);
	if (!di) {
		ret = -ENODATA;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 #include "xattr.h"
 #include "disk-io.h"
 #include "props.h"
+#include "locking.h"
 
 
 ssize_t __btrfs_getxattr(struct inode *inode, const char *name,
@@ -91,7 +92,7 @@
 		       struct inode *inode, const char *name,
 		       const void *value, size_t size, int flags)
 {
-	struct btrfs_dir_item *di;
+	struct btrfs_dir_item *di = NULL;
 	struct btrfs_root *root = BTRFS_I(inode)->root;
 	struct btrfs_path *path;
 	size_t name_len = strlen(name);
@@ -103,84 +104,119 @@
 	path = btrfs_alloc_path();
 	if (!path)
 		return -ENOMEM;
-
+	path->skip_release_on_error = 1;
+
+	if (!value) {
+		di = btrfs_lookup_xattr(trans, root, path, btrfs_ino(inode),
+					name, name_len, -1);
+		if (!di && (flags & XATTR_REPLACE))
+			ret = -ENODATA;
+		else if (di)
+			ret = btrfs_delete_one_dir_name(trans, root, path, di);
+		goto out;
+	}
+
+	/*
+	 * For a replace we can't just do the insert blindly.
+	 * Do a lookup first (read-only btrfs_search_slot), and return if xattr
+	 * doesn't exist. If it exists, fall down below to the insert/replace
+	 * path - we can't race with a concurrent xattr delete, because the VFS
+	 * locks the inode's i_mutex before calling setxattr or removexattr.
+	 */
 	if (flags & XATTR_REPLACE) {
-		di = btrfs_lookup_xattr(trans, root, path, btrfs_ino(inode), name,
-					name_len, -1);
-		if (IS_ERR(di)) {
-			ret = PTR_ERR(di);
-			goto out;
-		} else if (!di) {
+		ASSERT(mutex_is_locked(&inode->i_mutex));
+		di = btrfs_lookup_xattr(NULL, root, path, btrfs_ino(inode),
+					name, name_len, 0);
+		if (!di) {
 			ret = -ENODATA;
 			goto out;
 		}
-		ret = btrfs_delete_one_dir_name(trans, root, path, di);
-		if (ret)
-			goto out;
 		btrfs_release_path(path);
-
-		/*
-		 * remove the attribute
-		 */
-		if (!value)
-			goto out;
-	} else {
-		di = btrfs_lookup_xattr(NULL, root, path, btrfs_ino(inode),
-					name, name_len, 0);
-		if (IS_ERR(di)) {
-			ret = PTR_ERR(di);
-			goto out;
-		}
-		if (!di && !value)
-			goto out;
-		btrfs_release_path(path);
-	}
-
-again:
+		di = NULL;
+	}
+
 	ret = btrfs_insert_xattr_item(trans, root, path, btrfs_ino(inode),
 				      name, name_len, value, size);
-	/*
-	 * If we're setting an xattr to a new value but the new value is say
-	 * exactly BTRFS_MAX_XATTR_SIZE, we could end up with EOVERFLOW getting
-	 * back from split_leaf.  This is because it thinks we'll be extending
-	 * the existing item size, but we're asking for enough space to add the
-	 * item itself.  So if we get EOVERFLOW just set ret to EEXIST and let
-	 * the rest of the function figure it out.
-	 */
-	if (ret == -EOVERFLOW)
+	if (ret == -EOVERFLOW) {
+		/*
+		 * We have an existing item in a leaf, split_leaf couldn't
+		 * expand it. That item might have or not a dir_item that
+		 * matches our target xattr, so lets check.
+		 */
+		ret = 0;
+		btrfs_assert_tree_locked(path->nodes[0]);
+		di = btrfs_match_dir_item_name(root, path, name, name_len);
+		if (!di && !(flags & XATTR_REPLACE)) {
+			ret = -ENOSPC;
+			goto out;
+		}
+	} else if (ret == -EEXIST) {
+		ret = 0;
+		di = btrfs_match_dir_item_name(root, path, name, name_len);
+		ASSERT(di); /* logic error */
+	} else if (ret) {
+		goto out;
+	}
+
+	if (di && (flags & XATTR_CREATE)) {
 		ret = -EEXIST;
-
-	if (ret == -EEXIST) {
-		if (flags & XATTR_CREATE)
-			goto out;
+		goto out;
+	}
+
+	if (di) {
 		/*
-		 * We can't use the path we already have since we won't have the
-		 * proper locking for a delete, so release the path and
-		 * re-lookup to delete the thing.
+		 * We're doing a replace, and it must be atomic, that is, at
+		 * any point in time we have either the old or the new xattr
+		 * value in the tree. We don't want readers (getxattr and
+		 * listxattrs) to miss a value, this is specially important
+		 * for ACLs.
 		 */
-		btrfs_release_path(path);
-		di = btrfs_lookup_xattr(trans, root, path, btrfs_ino(inode),
-					name, name_len, -1);
-		if (IS_ERR(di)) {
-			ret = PTR_ERR(di);
-			goto out;
-		} else if (!di) {
-			/* Shouldn't happen but just in case... */
-			btrfs_release_path(path);
-			goto again;
-		}
-
-		ret = btrfs_delete_one_dir_name(trans, root, path, di);
-		if (ret)
-			goto out;
-
+		const int slot = path->slots[0];
+		struct extent_buffer *leaf = path->nodes[0];
+		const u16 old_data_len = btrfs_dir_data_len(leaf, di);
+		const u32 item_size = btrfs_item_size_nr(leaf, slot);
+		const u32 data_size = sizeof(*di) + name_len + size;
+		struct btrfs_item *item;
+		unsigned long data_ptr;
+		char *ptr;
+
+		if (size > old_data_len) {
+			if (btrfs_leaf_free_space(root, leaf) <
+			    (size - old_data_len)) {
+				ret = -ENOSPC;
+				goto out;
+			}
+		}
+
+		if (old_data_len + name_len + sizeof(*di) == item_size) {
+			/* No other xattrs packed in the same leaf item. */
+			if (size > old_data_len)
+				btrfs_extend_item(root, path,
+						  size - old_data_len);
+			else if (size < old_data_len)
+				btrfs_truncate_item(root, path, data_size, 1);
+		} else {
+			/* There are other xattrs packed in the same item. */
+			ret = btrfs_delete_one_dir_name(trans, root, path, di);
+			if (ret)
+				goto out;
+			btrfs_extend_item(root, path, data_size);
+		}
+
+		item = btrfs_item_nr(slot);
+		ptr = btrfs_item_ptr(leaf, slot, char);
+		ptr += btrfs_item_size(leaf, item) - data_size;
+		di = (struct btrfs_dir_item *)ptr;
+		btrfs_set_dir_data_len(leaf, di, size);
+		data_ptr = ((unsigned long)(di + 1)) + name_len;
+		write_extent_buffer(leaf, value, data_ptr, size);
+		btrfs_mark_buffer_dirty(leaf);
+	} else {
 		/*
-		 * We have a value to set, so go back and try to insert it now.
+		 * Insert, and we had space for the xattr, so path->slots[0] is
+		 * where our xattr dir_item is and btrfs_insert_xattr_item()
+		 * filled it.
 		 */
-		if (value) {
-			btrfs_release_path(path);
-			goto again;
-		}
 	}
 out:
 	btrfs_free_path(path);
```
