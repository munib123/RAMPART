# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1781_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1781_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 4200-4240 of the vulnerable file.

	btrfs_btree_balance_dirty(root);

	return err;
}

static int truncate_space_check(struct btrfs_trans_handle *trans,
				struct btrfs_root *root,
				u64 bytes_deleted)
{
	int ret;

	bytes_deleted = btrfs_csum_bytes_to_leaves(root, bytes_deleted);
	ret = btrfs_block_rsv_add(root, &root->fs_info->trans_block_rsv,
				  bytes_deleted, BTRFS_RESERVE_NO_FLUSH);
	if (!ret)
		trans->bytes_reserved += bytes_deleted;
	return ret;

}

/*
 * this can truncate away extent items, csum items and directory items.
 * It starts at a high offset and removes keys until it can't find
 * any higher than new_size
 *
 * csum items that cross the new i_size are truncated to the new size
 * as well.
 *
 * min_type is the minimum key type to truncate down to.  If set to 0, this
 * will kill all the items on this inode, including the INODE_ITEM_KEY.
 */
int btrfs_truncate_inode_items(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root,
			       struct inode *inode,
			       u64 new_size, u32 min_type)
{
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	struct btrfs_key found_key;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4217,6 +4217,47 @@
 
 }
 
+static int truncate_inline_extent(struct inode *inode,
+				  struct btrfs_path *path,
+				  struct btrfs_key *found_key,
+				  const u64 item_end,
+				  const u64 new_size)
+{
+	struct extent_buffer *leaf = path->nodes[0];
+	int slot = path->slots[0];
+	struct btrfs_file_extent_item *fi;
+	u32 size = (u32)(new_size - found_key->offset);
+	struct btrfs_root *root = BTRFS_I(inode)->root;
+
+	fi = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);
+
+	if (btrfs_file_extent_compression(leaf, fi) != BTRFS_COMPRESS_NONE) {
+		loff_t offset = new_size;
+		loff_t page_end = ALIGN(offset, PAGE_CACHE_SIZE);
+
+		/*
+		 * Zero out the remaining of the last page of our inline extent,
+		 * instead of directly truncating our inline extent here - that
+		 * would be much more complex (decompressing all the data, then
+		 * compressing the truncated data, which might be bigger than
+		 * the size of the inline extent, resize the extent, etc).
+		 * We release the path because to get the page we might need to
+		 * read the extent item from disk (data not in the page cache).
+		 */
+		btrfs_release_path(path);
+		return btrfs_truncate_page(inode, offset, page_end - offset, 0);
+	}
+
+	btrfs_set_file_extent_ram_bytes(leaf, fi, size);
+	size = btrfs_file_extent_calc_inline_size(size);
+	btrfs_truncate_item(root, path, size, 1);
+
+	if (test_bit(BTRFS_ROOT_REF_COWS, &root->state))
+		inode_sub_bytes(inode, item_end + 1 - new_size);
+
+	return 0;
+}
+
 /*
  * this can truncate away extent items, csum items and directory items.
  * It starts at a high offset and removes keys until it can't find
@@ -4411,27 +4452,40 @@
 			 * special encodings
 			 */
 			if (!del_item &&
-			    btrfs_file_extent_compression(leaf, fi) == 0 &&
 			    btrfs_file_extent_encryption(leaf, fi) == 0 &&
 			    btrfs_file_extent_other_encoding(leaf, fi) == 0) {
-				u32 size = new_size - found_key.offset;
-
-				if (test_bit(BTRFS_ROOT_REF_COWS, &root->state))
-					inode_sub_bytes(inode, item_end + 1 -
-							new_size);
 
 				/*
-				 * update the ram bytes to properly reflect
-				 * the new size of our item
+				 * Need to release path in order to truncate a
+				 * compressed extent. So delete any accumulated
+				 * extent items so far.
 				 */
-				btrfs_set_file_extent_ram_bytes(leaf, fi, size);
-				size =
-				    btrfs_file_extent_calc_inline_size(size);
-				btrfs_truncate_item(root, path, size, 1);
+				if (btrfs_file_extent_compression(leaf, fi) !=
+				    BTRFS_COMPRESS_NONE && pending_del_nr) {
+					err = btrfs_del_items(trans, root, path,
+							      pending_del_slot,
+							      pending_del_nr);
+					if (err) {
+						btrfs_abort_transaction(trans,
+									root,
+									err);
+						goto error;
+					}
+					pending_del_nr = 0;
+				}
+
+				err = truncate_inline_extent(inode, path,
+							     &found_key,
+							     item_end,
+							     new_size);
+				if (err) {
+					btrfs_abort_transaction(trans,
+								root, err);
+					goto error;
+				}
 			} else if (test_bit(BTRFS_ROOT_REF_COWS,
 					    &root->state)) {
-				inode_sub_bytes(inode, item_end + 1 -
-						found_key.offset);
+				inode_sub_bytes(inode, item_end + 1 - new_size);
 			}
 		}
 delete:
```
