# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3640_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3640_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1-36 of the vulnerable file.

#ifndef _LINUX_HUGETLB_H
#define _LINUX_HUGETLB_H

#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/hugetlb_inline.h>

struct ctl_table;
struct user_struct;

#ifdef CONFIG_HUGETLB_PAGE

#include <linux/mempolicy.h>
#include <linux/shm.h>
#include <asm/tlbflush.h>

int PageHuge(struct page *page);

void reset_vma_resv_huge_pages(struct vm_area_struct *vma);
int hugetlb_sysctl_handler(struct ctl_table *, int, void __user *, size_t *, loff_t *);
int hugetlb_overcommit_handler(struct ctl_table *, int, void __user *, size_t *, loff_t *);
int hugetlb_treat_movable_handler(struct ctl_table *, int, void __user *, size_t *, loff_t *);

#ifdef CONFIG_NUMA
int hugetlb_mempolicy_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
#endif

int copy_hugetlb_page_range(struct mm_struct *, struct mm_struct *, struct vm_area_struct *);
int follow_hugetlb_page(struct mm_struct *, struct vm_area_struct *,
			struct page **, struct vm_area_struct **,
			unsigned long *, int *, int, unsigned int flags);
void unmap_hugepage_range(struct vm_area_struct *,
			unsigned long, unsigned long, struct page *);
void __unmap_hugepage_range(struct vm_area_struct *,
			unsigned long, unsigned long, struct page *);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,15 @@
 #include <linux/mempolicy.h>
 #include <linux/shm.h>
 #include <asm/tlbflush.h>
+
+struct hugepage_subpool {
+	spinlock_t lock;
+	long count;
+	long max_hpages, used_hpages;
+};
+
+struct hugepage_subpool *hugepage_new_subpool(long nr_blocks);
+void hugepage_put_subpool(struct hugepage_subpool *spool);
 
 int PageHuge(struct page *page);
 
@@ -129,12 +138,11 @@
 
 #ifdef CONFIG_HUGETLBFS
 struct hugetlbfs_sb_info {
-	long	max_blocks;   /* blocks allowed */
-	long	free_blocks;  /* blocks free */
 	long	max_inodes;   /* inodes allowed */
 	long	free_inodes;  /* inodes free */
 	spinlock_t	stat_lock;
 	struct hstate *hstate;
+	struct hugepage_subpool *spool;
 };
 
 static inline struct hugetlbfs_sb_info *HUGETLBFS_SB(struct super_block *sb)
@@ -146,8 +154,6 @@
 extern const struct vm_operations_struct hugetlb_vm_ops;
 struct file *hugetlb_file_setup(const char *name, size_t size, vm_flags_t acct,
 				struct user_struct **user, int creat_flags);
-int hugetlb_get_quota(struct address_space *mapping, long delta);
-void hugetlb_put_quota(struct address_space *mapping, long delta);
 
 static inline int is_file_hugepages(struct file *file)
 {
```
