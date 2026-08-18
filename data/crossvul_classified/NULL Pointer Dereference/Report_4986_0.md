# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4986_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4986_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

 */

#include <linux/migrate.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/mm_inline.h>
#include <linux/nsproxy.h>
#include <linux/pagevec.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/writeback.h>
#include <linux/mempolicy.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/gfp.h>
#include <linux/balloon_compaction.h>
#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>

#include <asm/tlbflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/migrate.h>

#include "internal.h"

/*
 * migrate_prep() needs to be called before we start compiling a list of pages
 * to be migrated using isolate_lru_page(). If scheduling work on other CPUs is
 * undesirable, use migrate_prep_local()
 */
int migrate_prep(void)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,7 @@
 #include <linux/mempolicy.h>
 #include <linux/vmalloc.h>
 #include <linux/security.h>
+#include <linux/backing-dev.h>
 #include <linux/syscalls.h>
 #include <linux/hugetlb.h>
 #include <linux/hugetlb_cgroup.h>
@@ -313,6 +314,8 @@
 		struct buffer_head *head, enum migrate_mode mode,
 		int extra_count)
 {
+	struct zone *oldzone, *newzone;
+	int dirty;
 	int expected_count = 1 + extra_count;
 	void **pslot;
 
@@ -331,6 +334,9 @@
 		return MIGRATEPAGE_SUCCESS;
 	}
 
+	oldzone = page_zone(page);
+	newzone = page_zone(newpage);
+
 	spin_lock_irq(&mapping->tree_lock);
 
 	pslot = radix_tree_lookup_slot(&mapping->page_tree,
@@ -378,6 +384,13 @@
 		set_page_private(newpage, page_private(page));
 	}
 
+	/* Move dirty while page refs frozen and newpage not yet exposed */
+	dirty = PageDirty(page);
+	if (dirty) {
+		ClearPageDirty(page);
+		SetPageDirty(newpage);
+	}
+
 	radix_tree_replace_slot(pslot, newpage);
 
 	/*
@@ -386,6 +399,9 @@
 	 * We know this isn't the last reference.
 	 */
 	page_unfreeze_refs(page, expected_count - 1);
+
+	spin_unlock(&mapping->tree_lock);
+	/* Leave irq disabled to prevent preemption while updating stats */
 
 	/*
 	 * If moved to a different zone then also account
@@ -397,13 +413,19 @@
 	 * via NR_FILE_PAGES and NR_ANON_PAGES if they
 	 * are mapped to swap space.
 	 */
-	__dec_zone_page_state(page, NR_FILE_PAGES);
-	__inc_zone_page_state(newpage, NR_FILE_PAGES);
-	if (!PageSwapCache(page) && PageSwapBacked(page)) {
-		__dec_zone_page_state(page, NR_SHMEM);
-		__inc_zone_page_state(newpage, NR_SHMEM);
-	}
-	spin_unlock_irq(&mapping->tree_lock);
+	if (newzone != oldzone) {
+		__dec_zone_state(oldzone, NR_FILE_PAGES);
+		__inc_zone_state(newzone, NR_FILE_PAGES);
+		if (PageSwapBacked(page) && !PageSwapCache(page)) {
+			__dec_zone_state(oldzone, NR_SHMEM);
+			__inc_zone_state(newzone, NR_SHMEM);
+		}
+		if (dirty && mapping_cap_account_dirty(mapping)) {
+			__dec_zone_state(oldzone, NR_FILE_DIRTY);
+			__inc_zone_state(newzone, NR_FILE_DIRTY);
+		}
+	}
+	local_irq_enable();
 
 	return MIGRATEPAGE_SUCCESS;
 }
@@ -524,20 +546,9 @@
 	if (PageMappedToDisk(page))
 		SetPageMappedToDisk(newpage);
 
-	if (PageDirty(page)) {
-		clear_page_dirty_for_io(page);
-		/*
-		 * Want to mark the page and the radix tree as dirty, and
-		 * redo the accounting that clear_page_dirty_for_io undid,
-		 * but we can't use set_page_dirty because that function
-		 * is actually a signal that all of the page has become dirty.
-		 * Whereas only part of our page may be dirty.
-		 */
-		if (PageSwapBacked(page))
-			SetPageDirty(newpage);
-		else
-			__set_page_dirty_nobuffers(newpage);
- 	}
+	/* Move dirty on pages not done by migrate_page_move_mapping() */
+	if (PageDirty(page))
+		SetPageDirty(newpage);
 
 	if (page_is_young(page))
 		set_page_young(newpage);
```
