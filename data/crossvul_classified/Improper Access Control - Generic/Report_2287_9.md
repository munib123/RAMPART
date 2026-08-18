# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2287_9
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2287_9`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 26-66 of the vulnerable file.

#include <asm/uaccess.h>
#include "internal.h"

static int ramfs_nommu_setattr(struct dentry *, struct iattr *);
static unsigned long ramfs_nommu_get_unmapped_area(struct file *file,
						   unsigned long addr,
						   unsigned long len,
						   unsigned long pgoff,
						   unsigned long flags);
static int ramfs_nommu_mmap(struct file *file, struct vm_area_struct *vma);

const struct file_operations ramfs_file_operations = {
	.mmap			= ramfs_nommu_mmap,
	.get_unmapped_area	= ramfs_nommu_get_unmapped_area,
	.read			= new_sync_read,
	.read_iter		= generic_file_read_iter,
	.write			= new_sync_write,
	.write_iter		= generic_file_write_iter,
	.fsync			= noop_fsync,
	.splice_read		= generic_file_splice_read,
	.splice_write		= generic_file_splice_write,
	.llseek			= generic_file_llseek,
};

const struct inode_operations ramfs_file_inode_operations = {
	.setattr		= ramfs_nommu_setattr,
	.getattr		= simple_getattr,
};

/*****************************************************************************/
/*
 * add a contiguous set of pages into a ramfs inode when it's truncated from
 * size 0 on the assumption that it's going to be used for an mmap of shared
 * memory
 */
int ramfs_nommu_expand_for_mapping(struct inode *inode, size_t newsize)
{
	unsigned long npages, xpages, loop;
	struct page *pages;
	unsigned order;
	void *data;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
 	.write_iter		= generic_file_write_iter,
 	.fsync			= noop_fsync,
 	.splice_read		= generic_file_splice_read,
-	.splice_write		= generic_file_splice_write,
+	.splice_write		= iter_file_splice_write,
 	.llseek			= generic_file_llseek,
 };
 
```
