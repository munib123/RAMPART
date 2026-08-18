# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1317_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1317_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-37 of the vulnerable file.

// SPDX-License-Identifier: GPL-2.0
/*
 * fs/f2fs/data.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/prefetch.h>
#include <linux/uio.h>
#include <linux/cleancache.h>
#include <linux/sched/signal.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "trace.h"
#include <trace/events/f2fs.h>

#define NUM_PREALLOC_POST_READ_CTXS	128

static struct kmem_cache *bio_post_read_ctx_cache;
static mempool_t *bio_post_read_ctx_pool;

static bool __is_cp_guaranteed(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode;
	struct f2fs_sb_info *sbi;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,7 @@
 #include <linux/pagevec.h>
 #include <linux/blkdev.h>
 #include <linux/bio.h>
+#include <linux/swap.h>
 #include <linux/prefetch.h>
 #include <linux/uio.h>
 #include <linux/cleancache.h>
@@ -54,7 +55,7 @@
 
 static enum count_type __read_io_type(struct page *page)
 {
-	struct address_space *mapping = page->mapping;
+	struct address_space *mapping = page_file_mapping(page);
 
 	if (mapping) {
 		struct inode *inode = mapping->host;
@@ -1585,7 +1586,7 @@
 	sector_t block_nr;
 	int ret = 0;
 
-	block_in_file = (sector_t)page->index;
+	block_in_file = (sector_t)page_index(page);
 	last_block = block_in_file + nr_pages;
 	last_block_in_file = (i_size_read(inode) + blocksize - 1) >>
 							blkbits;
@@ -1618,7 +1619,8 @@
 		block_nr = map->m_pblk + block_in_file - map->m_lblk;
 		SetPageMappedToDisk(page);
 
-		if (!PageUptodate(page) && !cleancache_get_page(page)) {
+		if (!PageUptodate(page) && (!PageSwapCache(page) &&
+					!cleancache_get_page(page))) {
 			SetPageUptodate(page);
 			goto confused;
 		}
@@ -1716,7 +1718,7 @@
 			prefetchw(&page->flags);
 			list_del(&page->lru);
 			if (add_to_page_cache_lru(page, mapping,
-						  page->index,
+						  page_index(page),
 						  readahead_gfp_mask(mapping)))
 				goto next_page;
 		}
@@ -1740,7 +1742,7 @@
 
 static int f2fs_read_data_page(struct file *file, struct page *page)
 {
-	struct inode *inode = page->mapping->host;
+	struct inode *inode = page_file_mapping(page)->host;
 	int ret = -EAGAIN;
 
 	trace_f2fs_readpage(page, DATA);
@@ -1749,7 +1751,8 @@
 	if (f2fs_has_inline_data(inode))
 		ret = f2fs_read_inline_data(inode, page);
 	if (ret == -EAGAIN)
-		ret = f2fs_mpage_readpages(page->mapping, NULL, page, 1, false);
+		ret = f2fs_mpage_readpages(page_file_mapping(page),
+						NULL, page, 1, false);
 	return ret;
 }
 
@@ -2851,13 +2854,14 @@
 
 static int f2fs_set_data_page_dirty(struct page *page)
 {
-	struct address_space *mapping = page->mapping;
-	struct inode *inode = mapping->host;
+	struct inode *inode = page_file_mapping(page)->host;
 
 	trace_f2fs_set_page_dirty(page, DATA);
 
 	if (!PageUptodate(page))
 		SetPageUptodate(page);
+	if (PageSwapCache(page))
+		return __set_page_dirty_nobuffers(page);
 
 	if (f2fs_is_atomic_file(inode) && !f2fs_is_commit_atomic_write(inode)) {
 		if (!IS_ATOMIC_WRITTEN_PAGE(page)) {
@@ -2946,6 +2950,126 @@
 		migrate_page_states(newpage, page);
 
 	return MIGRATEPAGE_SUCCESS;
+}
+#endif
+
+#ifdef CONFIG_SWAP
+/* Copied from generic_swapfile_activate() to check any holes */
+static int check_swap_activate(struct file *swap_file, unsigned int max)
+{
+	struct address_space *mapping = swap_file->f_mapping;
+	struct inode *inode = mapping->host;
+	unsigned blocks_per_page;
+	unsigned long page_no;
+	unsigned blkbits;
+	sector_t probe_block;
+	sector_t last_block;
+	sector_t lowest_block = -1;
+	sector_t highest_block = 0;
+
+	blkbits = inode->i_blkbits;
+	blocks_per_page = PAGE_SIZE >> blkbits;
+
+	/*
+	 * Map all the blocks into the extent list.  This code doesn't try
+	 * to be very smart.
+	 */
+	probe_block = 0;
+	page_no = 0;
+	last_block = i_size_read(inode) >> blkbits;
+	while ((probe_block + blocks_per_page) <= last_block && page_no < max) {
+		unsigned block_in_page;
+		sector_t first_block;
+
+		cond_resched();
+
+		first_block = bmap(inode, probe_block);
+		if (first_block == 0)
+			goto bad_bmap;
+
+		/*
+		 * It must be PAGE_SIZE aligned on-disk
+		 */
+		if (first_block & (blocks_per_page - 1)) {
+			probe_block++;
+			goto reprobe;
+		}
+
+		for (block_in_page = 1; block_in_page < blocks_per_page;
+					block_in_page++) {
+			sector_t block;
+
+			block = bmap(inode, probe_block + block_in_page);
+			if (block == 0)
+				goto bad_bmap;
+			if (block != first_block + block_in_page) {
+				/* Discontiguity */
+				probe_block++;
+				goto reprobe;
+			}
+		}
+
+		first_block >>= (PAGE_SHIFT - blkbits);
+		if (page_no) {	/* exclude the header page */
+			if (first_block < lowest_block)
+				lowest_block = first_block;
+			if (first_block > highest_block)
+				highest_block = first_block;
+		}
+
+		page_no++;
+		probe_block += blocks_per_page;
+reprobe:
+		continue;
+	}
+	return 0;
+
+bad_bmap:
+	pr_err("swapon: swapfile has holes\n");
+	return -EINVAL;
+}
+
+static int f2fs_swap_activate(struct swap_info_struct *sis, struct file *file,
+				sector_t *span)
+{
+	struct inode *inode = file_inode(file);
+	int ret;
+
+	if (!S_ISREG(inode->i_mode))
+		return -EINVAL;
+
+	if (f2fs_readonly(F2FS_I_SB(inode)->sb))
+		return -EROFS;
+
+	ret = f2fs_convert_inline_inode(inode);
+	if (ret)
+		return ret;
+
+	ret = check_swap_activate(file, sis->max);
+	if (ret)
+		return ret;
+
+	set_inode_flag(inode, FI_PIN_FILE);
+	f2fs_precache_extents(inode);
+	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
+	return 0;
+}
+
+static void f2fs_swap_deactivate(struct file *file)
+{
+	struct inode *inode = file_inode(file);
+
+	clear_inode_flag(inode, FI_PIN_FILE);
+}
+#else
+static int f2fs_swap_activate(struct swap_info_struct *sis, struct file *file,
+				sector_t *span)
+{
+	return -EOPNOTSUPP;
+}
+
+static void f2fs_swap_deactivate(struct file *file)
+{
 }
 #endif
 
@@ -2961,6 +3085,8 @@
 	.releasepage	= f2fs_release_page,
 	.direct_IO	= f2fs_direct_IO,
 	.bmap		= f2fs_bmap,
+	.swap_activate  = f2fs_swap_activate,
+	.swap_deactivate = f2fs_swap_deactivate,
 #ifdef CONFIG_MIGRATION
 	.migratepage    = f2fs_migrate_page,
 #endif
```
