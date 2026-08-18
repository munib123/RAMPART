# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3012_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3012_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2508-2548 of the vulnerable file.

int __init create_node_manager_caches(void);
void destroy_node_manager_caches(void);

/*
 * segment.c
 */
bool need_SSR(struct f2fs_sb_info *sbi);
void register_inmem_page(struct inode *inode, struct page *page);
void drop_inmem_pages(struct inode *inode);
void drop_inmem_page(struct inode *inode, struct page *page);
int commit_inmem_pages(struct inode *inode);
void f2fs_balance_fs(struct f2fs_sb_info *sbi, bool need);
void f2fs_balance_fs_bg(struct f2fs_sb_info *sbi);
int f2fs_issue_flush(struct f2fs_sb_info *sbi);
int create_flush_cmd_control(struct f2fs_sb_info *sbi);
void destroy_flush_cmd_control(struct f2fs_sb_info *sbi, bool free);
void invalidate_blocks(struct f2fs_sb_info *sbi, block_t addr);
bool is_checkpointed_data(struct f2fs_sb_info *sbi, block_t blkaddr);
void refresh_sit_entry(struct f2fs_sb_info *sbi, block_t old, block_t new);
void stop_discard_thread(struct f2fs_sb_info *sbi);
void f2fs_wait_discard_bios(struct f2fs_sb_info *sbi);
void clear_prefree_segments(struct f2fs_sb_info *sbi, struct cp_control *cpc);
void release_discard_addrs(struct f2fs_sb_info *sbi);
int npages_for_summary_flush(struct f2fs_sb_info *sbi, bool for_ra);
void allocate_new_segments(struct f2fs_sb_info *sbi);
int f2fs_trim_fs(struct f2fs_sb_info *sbi, struct fstrim_range *range);
bool exist_trim_candidates(struct f2fs_sb_info *sbi, struct cp_control *cpc);
struct page *get_sum_page(struct f2fs_sb_info *sbi, unsigned int segno);
void update_meta_page(struct f2fs_sb_info *sbi, void *src, block_t blk_addr);
void write_meta_page(struct f2fs_sb_info *sbi, struct page *page,
						enum iostat_type io_type);
void write_node_page(unsigned int nid, struct f2fs_io_info *fio);
void write_data_page(struct dnode_of_data *dn, struct f2fs_io_info *fio);
int rewrite_data_page(struct f2fs_io_info *fio);
void __f2fs_replace_block(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
			block_t old_blkaddr, block_t new_blkaddr,
			bool recover_curseg, bool recover_newaddr);
void f2fs_replace_block(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
			block_t old_addr, block_t new_addr,
			unsigned char version, bool recover_curseg,
			bool recover_newaddr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2525,7 +2525,7 @@
 bool is_checkpointed_data(struct f2fs_sb_info *sbi, block_t blkaddr);
 void refresh_sit_entry(struct f2fs_sb_info *sbi, block_t old, block_t new);
 void stop_discard_thread(struct f2fs_sb_info *sbi);
-void f2fs_wait_discard_bios(struct f2fs_sb_info *sbi);
+void f2fs_wait_discard_bios(struct f2fs_sb_info *sbi, bool umount);
 void clear_prefree_segments(struct f2fs_sb_info *sbi, struct cp_control *cpc);
 void release_discard_addrs(struct f2fs_sb_info *sbi);
 int npages_for_summary_flush(struct f2fs_sb_info *sbi, bool for_ra);
```
