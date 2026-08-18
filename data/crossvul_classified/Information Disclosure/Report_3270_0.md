# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3270_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3270_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 667-707 of the vulnerable file.

				EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		if (!(flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) &&
		    !(status & EXTENT_STATUS_WRITTEN) &&
		    ext4_find_delalloc_range(inode, map->m_lblk,
					     map->m_lblk + map->m_len - 1))
			status |= EXTENT_STATUS_DELAYED;
		ret = ext4_es_insert_extent(inode, map->m_lblk, map->m_len,
					    map->m_pblk, status);
		if (ret < 0) {
			retval = ret;
			goto out_sem;
		}
	}

out_sem:
	up_write((&EXT4_I(inode)->i_data_sem));
	if (retval > 0 && map->m_flags & EXT4_MAP_MAPPED) {
		ret = check_block_validity(inode, map);
		if (ret != 0)
			return ret;
	}
	return retval;
}

/*
 * Update EXT4_MAP_FLAGS in bh->b_state. For buffer heads attached to pages
 * we have to be careful as someone else may be manipulating b_state as well.
 */
static void ext4_update_bh_state(struct buffer_head *bh, unsigned long flags)
{
	unsigned long old_state;
	unsigned long new_state;

	flags &= EXT4_MAP_FLAGS;

	/* Dummy buffer_head? Set non-atomically. */
	if (!bh->b_page) {
		bh->b_state = (bh->b_state & ~EXT4_MAP_FLAGS) | flags;
		return;
	}
	/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -684,6 +684,21 @@
 		ret = check_block_validity(inode, map);
 		if (ret != 0)
 			return ret;
+
+		/*
+		 * Inodes with freshly allocated blocks where contents will be
+		 * visible after transaction commit must be on transaction's
+		 * ordered data list.
+		 */
+		if (map->m_flags & EXT4_MAP_NEW &&
+		    !(map->m_flags & EXT4_MAP_UNWRITTEN) &&
+		    !(flags & EXT4_GET_BLOCKS_ZERO) &&
+		    !IS_NOQUOTA(inode) &&
+		    ext4_should_order_data(inode)) {
+			ret = ext4_jbd2_file_inode(handle, inode);
+			if (ret)
+				return ret;
+		}
 	}
 	return retval;
 }
@@ -1289,15 +1304,6 @@
 	int i_size_changed = 0;
 
 	trace_ext4_write_end(inode, pos, len, copied);
-	if (ext4_test_inode_state(inode, EXT4_STATE_ORDERED_MODE)) {
-		ret = ext4_jbd2_file_inode(handle, inode);
-		if (ret) {
-			unlock_page(page);
-			put_page(page);
-			goto errout;
-		}
-	}
-
 	if (ext4_has_inline_data(inode)) {
 		ret = ext4_write_inline_data_end(inode, pos, len,
 						 copied, page);
```
