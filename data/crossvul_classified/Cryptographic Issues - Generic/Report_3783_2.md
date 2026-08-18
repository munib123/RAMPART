# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 3783_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3783_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 4868-4908 of the vulnerable file.

		btrfs_set_key_type(&key, BTRFS_INODE_ITEM_KEY);
		key.offset = 0;
	}

	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID)) {
		ret = btrfs_add_root_ref(trans, root->fs_info->tree_root,
					 key.objectid, root->root_key.objectid,
					 parent_ino, index, name, name_len);
	} else if (add_backref) {
		ret = btrfs_insert_inode_ref(trans, root, name, name_len, ino,
					     parent_ino, index);
	}

	/* Nothing to clean up yet */
	if (ret)
		return ret;

	ret = btrfs_insert_dir_item(trans, root, name, name_len,
				    parent_inode, &key,
				    btrfs_inode_type(inode), index);
	if (ret == -EEXIST)
		goto fail_dir_item;
	else if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		return ret;
	}

	btrfs_i_size_write(parent_inode, parent_inode->i_size +
			   name_len * 2);
	inode_inc_iversion(parent_inode);
	parent_inode->i_mtime = parent_inode->i_ctime = CURRENT_TIME;
	ret = btrfs_update_inode(trans, root, parent_inode);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
	return ret;

fail_dir_item:
	if (unlikely(ino == BTRFS_FIRST_FREE_OBJECTID)) {
		u64 local_index;
		int err;
		err = btrfs_del_root_ref(trans, root->fs_info->tree_root,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4885,7 +4885,7 @@
 	ret = btrfs_insert_dir_item(trans, root, name, name_len,
 				    parent_inode, &key,
 				    btrfs_inode_type(inode), index);
-	if (ret == -EEXIST)
+	if (ret == -EEXIST || ret == -EOVERFLOW)
 		goto fail_dir_item;
 	else if (ret) {
 		btrfs_abort_transaction(trans, root, ret);
@@ -7336,6 +7336,28 @@
 	if (S_ISDIR(old_inode->i_mode) && new_inode &&
 	    new_inode->i_size > BTRFS_EMPTY_DIR_SIZE)
 		return -ENOTEMPTY;
+
+
+	/* check for collisions, even if the  name isn't there */
+	ret = btrfs_check_dir_item_collision(root, new_dir->i_ino,
+			     new_dentry->d_name.name,
+			     new_dentry->d_name.len);
+
+	if (ret) {
+		if (ret == -EEXIST) {
+			/* we shouldn't get
+			 * eexist without a new_inode */
+			if (!new_inode) {
+				WARN_ON(1);
+				return ret;
+			}
+		} else {
+			/* maybe -EOVERFLOW */
+			return ret;
+		}
+	}
+	ret = 0;
+
 	/*
 	 * we're using rename to replace one file with another.
 	 * and the replacement file is large.  Start IO on it now so
```
