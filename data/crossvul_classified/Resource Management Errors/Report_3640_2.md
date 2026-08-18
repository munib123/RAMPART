# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3640_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3640_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 35-75 of the vulnerable file.

unsigned long hugepages_treat_as_movable;

static int max_hstate;
unsigned int default_hstate_idx;
struct hstate hstates[HUGE_MAX_HSTATE];

__initdata LIST_HEAD(huge_boot_pages);

/* for command line parsing */
static struct hstate * __initdata parsed_hstate;
static unsigned long __initdata default_hstate_max_huge_pages;
static unsigned long __initdata default_hstate_size;

#define for_each_hstate(h) \
	for ((h) = hstates; (h) < &hstates[max_hstate]; (h)++)

/*
 * Protects updates to hugepage_freelists, nr_huge_pages, and free_huge_pages
 */
static DEFINE_SPINLOCK(hugetlb_lock);

/*
 * Region tracking -- allows tracking of reservations and instantiated pages
 *                    across the pages in a mapping.
 *
 * The region data structures are protected by a combination of the mmap_sem
 * and the hugetlb_instantion_mutex.  To access or modify a region the caller
 * must either hold the mmap_sem for write, or the mmap_sem for read and
 * the hugetlb_instantiation mutex:
 *
 *	down_write(&mm->mmap_sem);
 * or
 *	down_read(&mm->mmap_sem);
 *	mutex_lock(&hugetlb_instantiation_mutex);
 */
struct file_region {
	struct list_head link;
	long from;
	long to;
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,6 +53,84 @@
  */
 static DEFINE_SPINLOCK(hugetlb_lock);
 
+static inline void unlock_or_release_subpool(struct hugepage_subpool *spool)
+{
+	bool free = (spool->count == 0) && (spool->used_hpages == 0);
+
+	spin_unlock(&spool->lock);
+
+	/* If no pages are used, and no other handles to the subpool
+	 * remain, free the subpool the subpool remain */
+	if (free)
+		kfree(spool);
+}
+
+struct hugepage_subpool *hugepage_new_subpool(long nr_blocks)
+{
+	struct hugepage_subpool *spool;
+
+	spool = kmalloc(sizeof(*spool), GFP_KERNEL);
+	if (!spool)
+		return NULL;
+
+	spin_lock_init(&spool->lock);
+	spool->count = 1;
+	spool->max_hpages = nr_blocks;
+	spool->used_hpages = 0;
+
+	return spool;
+}
+
+void hugepage_put_subpool(struct hugepage_subpool *spool)
+{
+	spin_lock(&spool->lock);
+	BUG_ON(!spool->count);
+	spool->count--;
+	unlock_or_release_subpool(spool);
+}
+
+static int hugepage_subpool_get_pages(struct hugepage_subpool *spool,
+				      long delta)
+{
+	int ret = 0;
+
+	if (!spool)
+		return 0;
+
+	spin_lock(&spool->lock);
+	if ((spool->used_hpages + delta) <= spool->max_hpages) {
+		spool->used_hpages += delta;
+	} else {
+		ret = -ENOMEM;
+	}
+	spin_unlock(&spool->lock);
+
+	return ret;
+}
+
+static void hugepage_subpool_put_pages(struct hugepage_subpool *spool,
+				       long delta)
+{
+	if (!spool)
+		return;
+
+	spin_lock(&spool->lock);
+	spool->used_hpages -= delta;
+	/* If hugetlbfs_put_super couldn't free spool due to
+	* an outstanding quota reference, free it now. */
+	unlock_or_release_subpool(spool);
+}
+
+static inline struct hugepage_subpool *subpool_inode(struct inode *inode)
+{
+	return HUGETLBFS_SB(inode->i_sb)->spool;
+}
+
+static inline struct hugepage_subpool *subpool_vma(struct vm_area_struct *vma)
+{
+	return subpool_inode(vma->vm_file->f_dentry->d_inode);
+}
+
 /*
  * Region tracking -- allows tracking of reservations and instantiated pages
  *                    across the pages in a mapping.
@@ -540,9 +618,9 @@
 	 */
 	struct hstate *h = page_hstate(page);
 	int nid = page_to_nid(page);
-	struct address_space *mapping;
-
-	mapping = (struct address_space *) page_private(page);
+	struct hugepage_subpool *spool =
+		(struct hugepage_subpool *)page_private(page);
+
 	set_page_private(page, 0);
 	page->mapping = NULL;
 	BUG_ON(page_count(page));
@@ -558,8 +636,7 @@
 		enqueue_huge_page(h, page);
 	}
 	spin_unlock(&hugetlb_lock);
-	if (mapping)
-		hugetlb_put_quota(mapping, 1);
+	hugepage_subpool_put_pages(spool, 1);
 }
 
 static void prep_new_huge_page(struct hstate *h, struct page *page, int nid)
@@ -977,11 +1054,12 @@
 /*
  * Determine if the huge page at addr within the vma has an associated
  * reservation.  Where it does not we will need to logically increase
- * reservation and actually increase quota before an allocation can occur.
- * Where any new reservation would be required the reservation change is
- * prepared, but not committed.  Once the page has been quota'd allocated
- * an instantiated the change should be committed via vma_commit_reservation.
- * No action is required on failure.
+ * reservation and actually increase subpool usage before an allocation
+ * can occur.  Where any new reservation would be required the
+ * reservation change is prepared, but not committed.  Once the page
+ * has been allocated from the subpool and instantiated the change should
+ * be committed via vma_commit_reservation.  No action is required on
+ * failure.
  */
 static long vma_needs_reservation(struct hstate *h,
 			struct vm_area_struct *vma, unsigned long addr)
@@ -1030,24 +1108,24 @@
 static struct page *alloc_huge_page(struct vm_area_struct *vma,
 				    unsigned long addr, int avoid_reserve)
 {
+	struct hugepage_subpool *spool = subpool_vma(vma);
 	struct hstate *h = hstate_vma(vma);
 	struct page *page;
-	struct address_space *mapping = vma->vm_file->f_mapping;
-	struct inode *inode = mapping->host;
 	long chg;
 
 	/*
-	 * Processes that did not create the mapping will have no reserves and
-	 * will not have accounted against quota. Check that the quota can be
-	 * made before satisfying the allocation
-	 * MAP_NORESERVE mappings may also need pages and quota allocated
-	 * if no reserve mapping overlaps.
+	 * Processes that did not create the mapping will have no
+	 * reserves and will not have accounted against subpool
+	 * limit. Check that the subpool limit can be made before
+	 * satisfying the allocation MAP_NORESERVE mappings may also
+	 * need pages and subpool limit allocated allocated if no reserve
+	 * mapping overlaps.
 	 */
 	chg = vma_needs_reservation(h, vma, addr);
 	if (chg < 0)
 		return ERR_PTR(-VM_FAULT_OOM);
 	if (chg)
-		if (hugetlb_get_quota(inode->i_mapping, chg))
+		if (hugepage_subpool_get_pages(spool, chg))
 			return ERR_PTR(-VM_FAULT_SIGBUS);
 
 	spin_lock(&hugetlb_lock);
@@ -1057,12 +1135,12 @@
 	if (!page) {
 		page = alloc_buddy_huge_page(h, NUMA_NO_NODE);
 		if (!page) {
-			hugetlb_put_quota(inode->i_mapping, chg);
+			hugepage_subpool_put_pages(spool, chg);
 			return ERR_PTR(-VM_FAULT_SIGBUS);
 		}
 	}
 
-	set_page_private(page, (unsigned long) mapping);
+	set_page_private(page, (unsigned long)spool);
 
 	vma_commit_reservation(h, vma, addr);
 
@@ -2083,6 +2161,7 @@
 {
 	struct hstate *h = hstate_vma(vma);
 	struct resv_map *reservations = vma_resv_map(vma);
+	struct hugepage_subpool *spool = subpool_vma(vma);
 	unsigned long reserve;
 	unsigned long start;
 	unsigned long end;
@@ -2098,7 +2177,7 @@
 
 		if (reserve) {
 			hugetlb_acct_memory(h, -reserve);
-			hugetlb_put_quota(vma->vm_file->f_mapping, reserve);
+			hugepage_subpool_put_pages(spool, reserve);
 		}
 	}
 }
@@ -2331,7 +2410,7 @@
 	 */
 	address = address & huge_page_mask(h);
 	pgoff = vma_hugecache_offset(h, vma, address);
-	mapping = (struct address_space *)page_private(page);
+	mapping = vma->vm_file->f_dentry->d_inode->i_mapping;
 
 	/*
 	 * Take the mapping lock for the duration of the table walk. As
@@ -2884,11 +2963,12 @@
 {
 	long ret, chg;
 	struct hstate *h = hstate_inode(inode);
+	struct hugepage_subpool *spool = subpool_inode(inode);
 
 	/*
 	 * Only apply hugepage reservation if asked. At fault time, an
 	 * attempt will be made for VM_NORESERVE to allocate a page
-	 * and filesystem quota without using reserves
+	 * without using reserves
 	 */
 	if (vm_flags & VM_NORESERVE)
 		return 0;
@@ -2915,17 +2995,17 @@
 	if (chg < 0)
 		return chg;
 
-	/* There must be enough filesystem quota for the mapping */
-	if (hugetlb_get_quota(inode->i_mapping, chg))
+	/* There must be enough pages in the subpool for the mapping */
+	if (hugepage_subpool_get_pages(spool, chg))
 		return -ENOSPC;
 
 	/*
 	 * Check enough hugepages are available for the reservation.
-	 * Hand back the quota if there are not
+	 * Hand the pages back to the subpool if there are not
 	 */
 	ret = hugetlb_acct_memory(h, chg);
 	if (ret < 0) {
-		hugetlb_put_quota(inode->i_mapping, chg);
+		hugepage_subpool_put_pages(spool, chg);
 		return ret;
 	}
 
@@ -2949,12 +3029,13 @@
 {
 	struct hstate *h = hstate_inode(inode);
 	long chg = region_truncate(&inode->i_mapping->private_list, offset);
+	struct hugepage_subpool *spool = subpool_inode(inode);
 
 	spin_lock(&inode->i_lock);
 	inode->i_blocks -= (blocks_per_huge_page(h) * freed);
 	spin_unlock(&inode->i_lock);
 
-	hugetlb_put_quota(inode->i_mapping, (chg - freed));
+	hugepage_subpool_put_pages(spool, (chg - freed));
 	hugetlb_acct_memory(h, -(chg - freed));
 }
 
```
