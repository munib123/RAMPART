# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 3783_4
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3783_4`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 1173-1213 of the vulnerable file.

		goto fail;
	}

	ret = btrfs_reloc_post_snapshot(trans, pending);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto fail;
	}

	ret = btrfs_run_delayed_refs(trans, root, (unsigned long)-1);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto fail;
	}

	ret = btrfs_insert_dir_item(trans, parent_root,
				    dentry->d_name.name, dentry->d_name.len,
				    parent_inode, &key,
				    BTRFS_FT_DIR, index);
	/* We have check then name at the beginning, so it is impossible. */
	BUG_ON(ret == -EEXIST);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto fail;
	}

	btrfs_i_size_write(parent_inode, parent_inode->i_size +
					 dentry->d_name.len * 2);
	parent_inode->i_mtime = parent_inode->i_ctime = CURRENT_TIME;
	ret = btrfs_update_inode_fallback(trans, parent_root, parent_inode);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
fail:
	dput(parent);
	trans->block_rsv = rsv;
no_free_objectid:
	kfree(new_root_item);
root_item_alloc_fail:
	btrfs_free_path(path);
path_alloc_fail:
	btrfs_block_rsv_release(root, &pending->block_rsv, (u64)-1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1190,7 +1190,7 @@
 				    parent_inode, &key,
 				    BTRFS_FT_DIR, index);
 	/* We have check then name at the beginning, so it is impossible. */
-	BUG_ON(ret == -EEXIST);
+	BUG_ON(ret == -EEXIST || ret == -EOVERFLOW);
 	if (ret) {
 		btrfs_abort_transaction(trans, root, ret);
 		goto fail;
```
