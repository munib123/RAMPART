# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1317_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1317_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1481-1521 of the vulnerable file.

	return container_of(inode, struct f2fs_inode_info, vfs_inode);
}

static inline struct f2fs_sb_info *F2FS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct f2fs_sb_info *F2FS_I_SB(struct inode *inode)
{
	return F2FS_SB(inode->i_sb);
}

static inline struct f2fs_sb_info *F2FS_M_SB(struct address_space *mapping)
{
	return F2FS_I_SB(mapping->host);
}

static inline struct f2fs_sb_info *F2FS_P_SB(struct page *page)
{
	return F2FS_M_SB(page->mapping);
}

static inline struct f2fs_super_block *F2FS_RAW_SUPER(struct f2fs_sb_info *sbi)
{
	return (struct f2fs_super_block *)(sbi->raw_super);
}

static inline struct f2fs_checkpoint *F2FS_CKPT(struct f2fs_sb_info *sbi)
{
	return (struct f2fs_checkpoint *)(sbi->ckpt);
}

static inline struct f2fs_node *F2FS_NODE(struct page *page)
{
	return (struct f2fs_node *)page_address(page);
}

static inline struct f2fs_inode *F2FS_INODE(struct page *page)
{
	return &((struct f2fs_node *)page_address(page))->i;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1498,7 +1498,7 @@
 
 static inline struct f2fs_sb_info *F2FS_P_SB(struct page *page)
 {
-	return F2FS_M_SB(page->mapping);
+	return F2FS_M_SB(page_file_mapping(page));
 }
 
 static inline struct f2fs_super_block *F2FS_RAW_SUPER(struct f2fs_sb_info *sbi)
@@ -3683,7 +3683,8 @@
 	if (test_opt(sbi, LFS) && (rw == WRITE) &&
 				block_unaligned_IO(inode, iocb, iter))
 		return true;
-	if (is_sbi_flag_set(F2FS_I_SB(inode), SBI_CP_DISABLED))
+	if (is_sbi_flag_set(F2FS_I_SB(inode), SBI_CP_DISABLED) &&
+					!(inode->i_flags & S_SWAPFILE))
 		return true;
 
 	return false;
```
