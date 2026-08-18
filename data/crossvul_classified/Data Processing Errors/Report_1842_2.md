# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1842_2
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1842_2`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 36-76 of the vulnerable file.

 *   | value 3          | | growing upwards
 *   | value 2          | |
 *   +------------------+
 *
 * The header is followed by multiple entry descriptors. In disk blocks, the
 * entry descriptors are kept sorted. In inodes, they are unsorted. The
 * attribute values are aligned to the end of the block in no specific order.
 *
 * Locking strategy
 * ----------------
 * EXT4_I(inode)->i_file_acl is protected by EXT4_I(inode)->xattr_sem.
 * EA blocks are only changed if they are exclusive to an inode, so
 * holding xattr_sem also means that nothing but the EA block's reference
 * count can change. Multiple writers to the same block are synchronized
 * by the buffer lock.
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mbcache.h>
#include <linux/quotaops.h>
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"
#include "acl.h"

#ifdef EXT4_XATTR_DEBUG
# define ea_idebug(inode, f...) do { \
		printk(KERN_DEBUG "inode %s:%lu: ", \
			inode->i_sb->s_id, inode->i_ino); \
		printk(f); \
		printk("\n"); \
	} while (0)
# define ea_bdebug(bh, f...) do { \
		printk(KERN_DEBUG "block %pg:%lu: ",		   \
		       bh->b_bdev, (unsigned long) bh->b_blocknr); \
		printk(f); \
		printk("\n"); \
	} while (0)
#else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,7 @@
 #include <linux/init.h>
 #include <linux/fs.h>
 #include <linux/slab.h>
-#include <linux/mbcache.h>
+#include <linux/mbcache2.h>
 #include <linux/quotaops.h>
 #include "ext4_jbd2.h"
 #include "ext4.h"
@@ -78,10 +78,10 @@
 # define ea_bdebug(bh, fmt, ...)	no_printk(fmt, ##__VA_ARGS__)
 #endif
 
-static void ext4_xattr_cache_insert(struct mb_cache *, struct buffer_head *);
+static void ext4_xattr_cache_insert(struct mb2_cache *, struct buffer_head *);
 static struct buffer_head *ext4_xattr_cache_find(struct inode *,
 						 struct ext4_xattr_header *,
-						 struct mb_cache_entry **);
+						 struct mb2_cache_entry **);
 static void ext4_xattr_rehash(struct ext4_xattr_header *,
 			      struct ext4_xattr_entry *);
 static int ext4_xattr_list(struct dentry *dentry, char *buffer,
@@ -276,7 +276,7 @@
 	struct ext4_xattr_entry *entry;
 	size_t size;
 	int error;
-	struct mb_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
+	struct mb2_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
 
 	ea_idebug(inode, "name=%d.%s, buffer=%p, buffer_size=%ld",
 		  name_index, name, buffer, (long)buffer_size);
@@ -428,7 +428,7 @@
 	struct inode *inode = d_inode(dentry);
 	struct buffer_head *bh = NULL;
 	int error;
-	struct mb_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
+	struct mb2_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
 
 	ea_idebug(inode, "buffer=%p, buffer_size=%ld",
 		  buffer, (long)buffer_size);
@@ -545,11 +545,8 @@
 ext4_xattr_release_block(handle_t *handle, struct inode *inode,
 			 struct buffer_head *bh)
 {
-	struct mb_cache_entry *ce = NULL;
 	int error = 0;
-	struct mb_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
-
-	ce = mb_cache_entry_get(ext4_mb_cache, bh->b_bdev, bh->b_blocknr);
+
 	BUFFER_TRACE(bh, "get_write_access");
 	error = ext4_journal_get_write_access(handle, bh);
 	if (error)
@@ -557,9 +554,15 @@
 
 	lock_buffer(bh);
 	if (BHDR(bh)->h_refcount == cpu_to_le32(1)) {
+		__u32 hash = le32_to_cpu(BHDR(bh)->h_hash);
+
 		ea_bdebug(bh, "refcount now=0; freeing");
-		if (ce)
-			mb_cache_entry_free(ce);
+		/*
+		 * This must happen under buffer lock for
+		 * ext4_xattr_block_set() to reliably detect freed block
+		 */
+		mb2_cache_entry_delete_block(EXT4_GET_MB_CACHE(inode), hash,
+					     bh->b_blocknr);
 		get_bh(bh);
 		unlock_buffer(bh);
 		ext4_free_blocks(handle, inode, bh, 0, 1,
@@ -567,8 +570,6 @@
 				 EXT4_FREE_BLOCKS_FORGET);
 	} else {
 		le32_add_cpu(&BHDR(bh)->h_refcount, -1);
-		if (ce)
-			mb_cache_entry_release(ce);
 		/*
 		 * Beware of this ugliness: Releasing of xattr block references
 		 * from different inodes can race and so we have to protect
@@ -781,17 +782,15 @@
 	struct super_block *sb = inode->i_sb;
 	struct buffer_head *new_bh = NULL;
 	struct ext4_xattr_search *s = &bs->s;
-	struct mb_cache_entry *ce = NULL;
+	struct mb2_cache_entry *ce = NULL;
 	int error = 0;
-	struct mb_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
+	struct mb2_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
 
 #define header(x) ((struct ext4_xattr_header *)(x))
 
 	if (i->value && i->value_len > sb->s_blocksize)
 		return -ENOSPC;
 	if (s->base) {
-		ce = mb_cache_entry_get(ext4_mb_cache, bs->bh->b_bdev,
-					bs->bh->b_blocknr);
 		BUFFER_TRACE(bs->bh, "get_write_access");
 		error = ext4_journal_get_write_access(handle, bs->bh);
 		if (error)
@@ -799,10 +798,15 @@
 		lock_buffer(bs->bh);
 
 		if (header(s->base)->h_refcount == cpu_to_le32(1)) {
-			if (ce) {
-				mb_cache_entry_free(ce);
-				ce = NULL;
-			}
+			__u32 hash = le32_to_cpu(BHDR(bs->bh)->h_hash);
+
+			/*
+			 * This must happen under buffer lock for
+			 * ext4_xattr_block_set() to reliably detect modified
+			 * block
+			 */
+			mb2_cache_entry_delete_block(ext4_mb_cache, hash,
+						     bs->bh->b_blocknr);
 			ea_bdebug(bs->bh, "modifying in-place");
 			error = ext4_xattr_set_entry(i, s);
 			if (!error) {
@@ -826,10 +830,6 @@
 			int offset = (char *)s->here - bs->bh->b_data;
 
 			unlock_buffer(bs->bh);
-			if (ce) {
-				mb_cache_entry_release(ce);
-				ce = NULL;
-			}
 			ea_bdebug(bs->bh, "cloning");
 			s->base = kmalloc(bs->bh->b_size, GFP_NOFS);
 			error = -ENOMEM;
@@ -884,6 +884,31 @@
 				if (error)
 					goto cleanup_dquot;
 				lock_buffer(new_bh);
+				/*
+				 * We have to be careful about races with
+				 * freeing or rehashing of xattr block. Once we
+				 * hold buffer lock xattr block's state is
+				 * stable so we can check whether the block got
+				 * freed / rehashed or not.  Since we unhash
+				 * mbcache entry under buffer lock when freeing
+				 * / rehashing xattr block, checking whether
+				 * entry is still hashed is reliable.
+				 */
+				if (hlist_bl_unhashed(&ce->e_hash_list)) {
+					/*
+					 * Undo everything and check mbcache
+					 * again.
+					 */
+					unlock_buffer(new_bh);
+					dquot_free_block(inode,
+							 EXT4_C2B(EXT4_SB(sb),
+								  1));
+					brelse(new_bh);
+					mb2_cache_entry_put(ext4_mb_cache, ce);
+					ce = NULL;
+					new_bh = NULL;
+					goto inserted;
+				}
 				le32_add_cpu(&BHDR(new_bh)->h_refcount, 1);
 				ea_bdebug(new_bh, "reusing; refcount now=%d",
 					le32_to_cpu(BHDR(new_bh)->h_refcount));
@@ -894,7 +919,8 @@
 				if (error)
 					goto cleanup_dquot;
 			}
-			mb_cache_entry_release(ce);
+			mb2_cache_entry_touch(ext4_mb_cache, ce);
+			mb2_cache_entry_put(ext4_mb_cache, ce);
 			ce = NULL;
 		} else if (bs->bh && s->base == bs->bh->b_data) {
 			/* We were modifying this block in-place. */
@@ -959,7 +985,7 @@
 
 cleanup:
 	if (ce)
-		mb_cache_entry_release(ce);
+		mb2_cache_entry_put(ext4_mb_cache, ce);
 	brelse(new_bh);
 	if (!(bs->bh && s->base == bs->bh->b_data))
 		kfree(s->base);
@@ -1512,17 +1538,6 @@
 }
 
 /*
- * ext4_xattr_put_super()
- *
- * This is called when a file system is unmounted.
- */
-void
-ext4_xattr_put_super(struct super_block *sb)
-{
-	mb_cache_shrink(sb->s_bdev);
-}
-
-/*
  * ext4_xattr_cache_insert()
  *
  * Create a new entry in the extended attribute cache, and insert
@@ -1531,28 +1546,18 @@
  * Returns 0, or a negative error number on failure.
  */
 static void
-ext4_xattr_cache_insert(struct mb_cache *ext4_mb_cache, struct buffer_head *bh)
+ext4_xattr_cache_insert(struct mb2_cache *ext4_mb_cache, struct buffer_head *bh)
 {
 	__u32 hash = le32_to_cpu(BHDR(bh)->h_hash);
-	struct mb_cache_entry *ce;
 	int error;
 
-	ce = mb_cache_entry_alloc(ext4_mb_cache, GFP_NOFS);
-	if (!ce) {
-		ea_bdebug(bh, "out of memory");
-		return;
-	}
-	error = mb_cache_entry_insert(ce, bh->b_bdev, bh->b_blocknr, hash);
+	error = mb2_cache_entry_create(ext4_mb_cache, GFP_NOFS, hash,
+				       bh->b_blocknr);
 	if (error) {
-		mb_cache_entry_free(ce);
-		if (error == -EBUSY) {
+		if (error == -EBUSY)
 			ea_bdebug(bh, "already in cache");
-			error = 0;
-		}
-	} else {
+	} else
 		ea_bdebug(bh, "inserting [%x]", (int)hash);
-		mb_cache_entry_release(ce);
-	}
 }
 
 /*
@@ -1605,26 +1610,19 @@
  */
 static struct buffer_head *
 ext4_xattr_cache_find(struct inode *inode, struct ext4_xattr_header *header,
-		      struct mb_cache_entry **pce)
+		      struct mb2_cache_entry **pce)
 {
 	__u32 hash = le32_to_cpu(header->h_hash);
-	struct mb_cache_entry *ce;
-	struct mb_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
+	struct mb2_cache_entry *ce;
+	struct mb2_cache *ext4_mb_cache = EXT4_GET_MB_CACHE(inode);
 
 	if (!header->h_hash)
 		return NULL;  /* never share */
 	ea_idebug(inode, "looking for cached blocks [%x]", (int)hash);
-again:
-	ce = mb_cache_entry_find_first(ext4_mb_cache, inode->i_sb->s_bdev,
-				       hash);
+	ce = mb2_cache_entry_find_first(ext4_mb_cache, hash);
 	while (ce) {
 		struct buffer_head *bh;
 
-		if (IS_ERR(ce)) {
-			if (PTR_ERR(ce) == -EAGAIN)
-				goto again;
-			break;
-		}
 		bh = sb_bread(inode->i_sb, ce->e_block);
 		if (!bh) {
 			EXT4_ERROR_INODE(inode, "block %lu read error",
@@ -1640,7 +1638,7 @@
 			return bh;
 		}
 		brelse(bh);
... (diff truncated)
```
