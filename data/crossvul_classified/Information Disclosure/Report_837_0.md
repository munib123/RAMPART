# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 837_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `837_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1018-1058 of the vulnerable file.

 * - allocates all needed blocks (new leaf and all intermediate index blocks)
 * - makes decision where to split
 * - moves remaining extents and index entries (right to the split point)
 *   into the newly allocated blocks
 * - initializes subtree
 */
static int ext4_ext_split(handle_t *handle, struct inode *inode,
			  unsigned int flags,
			  struct ext4_ext_path *path,
			  struct ext4_extent *newext, int at)
{
	struct buffer_head *bh = NULL;
	int depth = ext_depth(inode);
	struct ext4_extent_header *neh;
	struct ext4_extent_idx *fidx;
	int i = at, k, m, a;
	ext4_fsblk_t newblock, oldblock;
	__le32 border;
	ext4_fsblk_t *ablocks = NULL; /* array of allocated blocks */
	int err = 0;

	/* make decision: where to split? */
	/* FIXME: now decision is simplest: at current extent */

	/* if current leaf will be split, then we should use
	 * border from split point */
	if (unlikely(path[depth].p_ext > EXT_MAX_EXTENT(path[depth].p_hdr))) {
		EXT4_ERROR_INODE(inode, "p_ext > EXT_MAX_EXTENT!");
		return -EFSCORRUPTED;
	}
	if (path[depth].p_ext != EXT_MAX_EXTENT(path[depth].p_hdr)) {
		border = path[depth].p_ext[1].ee_block;
		ext_debug("leaf will be split."
				" next leaf starts at %d\n",
				  le32_to_cpu(border));
	} else {
		border = newext->ee_block;
		ext_debug("leaf will be added."
				" next leaf starts at %d\n",
				le32_to_cpu(border));
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1035,6 +1035,7 @@
 	__le32 border;
 	ext4_fsblk_t *ablocks = NULL; /* array of allocated blocks */
 	int err = 0;
+	size_t ext_size = 0;
 
 	/* make decision: where to split? */
 	/* FIXME: now decision is simplest: at current extent */
@@ -1126,6 +1127,10 @@
 		le16_add_cpu(&neh->eh_entries, m);
 	}
 
+	/* zero out unused area in the extent block */
+	ext_size = sizeof(struct ext4_extent_header) +
+		sizeof(struct ext4_extent) * le16_to_cpu(neh->eh_entries);
+	memset(bh->b_data + ext_size, 0, inode->i_sb->s_blocksize - ext_size);
 	ext4_extent_block_csum_set(inode, neh);
 	set_buffer_uptodate(bh);
 	unlock_buffer(bh);
@@ -1205,6 +1210,11 @@
 				sizeof(struct ext4_extent_idx) * m);
 			le16_add_cpu(&neh->eh_entries, m);
 		}
+		/* zero out unused area in the extent block */
+		ext_size = sizeof(struct ext4_extent_header) +
+		   (sizeof(struct ext4_extent) * le16_to_cpu(neh->eh_entries));
+		memset(bh->b_data + ext_size, 0,
+			inode->i_sb->s_blocksize - ext_size);
 		ext4_extent_block_csum_set(inode, neh);
 		set_buffer_uptodate(bh);
 		unlock_buffer(bh);
@@ -1270,6 +1280,7 @@
 	ext4_fsblk_t newblock, goal = 0;
 	struct ext4_super_block *es = EXT4_SB(inode->i_sb)->s_es;
 	int err = 0;
+	size_t ext_size = 0;
 
 	/* Try to prepend new index to old one */
 	if (ext_depth(inode))
@@ -1295,9 +1306,11 @@
 		goto out;
 	}
 
+	ext_size = sizeof(EXT4_I(inode)->i_data);
 	/* move top-level index/leaf into new block */
-	memmove(bh->b_data, EXT4_I(inode)->i_data,
-		sizeof(EXT4_I(inode)->i_data));
+	memmove(bh->b_data, EXT4_I(inode)->i_data, ext_size);
+	/* zero out unused area in the extent block */
+	memset(bh->b_data + ext_size, 0, inode->i_sb->s_blocksize - ext_size);
 
 	/* set size of new block */
 	neh = ext_block_hdr(bh);
```
