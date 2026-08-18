# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3026_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3026_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 1744-1784 of the vulnerable file.

	return 0;
}

static void __remove_nid_from_list(struct f2fs_sb_info *sbi,
			struct free_nid *i, enum nid_list list, bool reuse)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);

	f2fs_bug_on(sbi, list == FREE_NID_LIST ? i->state != NID_NEW :
						i->state != NID_ALLOC);
	nm_i->nid_cnt[list]--;
	list_del(&i->list);
	if (!reuse)
		radix_tree_delete(&nm_i->free_nid_root, i->nid);
}

/* return if the nid is recognized as free */
static bool add_free_nid(struct f2fs_sb_info *sbi, nid_t nid, bool build)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i;
	struct nat_entry *ne;
	int err;

	/* 0 nid should not be used */
	if (unlikely(nid == 0))
		return false;

	if (build) {
		/* do not add allocated nids */
		ne = __lookup_nat_cache(nm_i, nid);
		if (ne && (!get_nat_flag(ne, IS_CHECKPOINTED) ||
				nat_get_blkaddr(ne) != NULL_ADDR))
			return false;
	}

	i = f2fs_kmem_cache_alloc(free_nid_slab, GFP_NOFS);
	i->nid = nid;
	i->state = NID_NEW;

	if (radix_tree_preload(GFP_NOFS)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1761,40 +1761,67 @@
 static bool add_free_nid(struct f2fs_sb_info *sbi, nid_t nid, bool build)
 {
 	struct f2fs_nm_info *nm_i = NM_I(sbi);
-	struct free_nid *i;
+	struct free_nid *i, *e;
 	struct nat_entry *ne;
-	int err;
+	int err = -EINVAL;
+	bool ret = false;
 
 	/* 0 nid should not be used */
 	if (unlikely(nid == 0))
 		return false;
 
+	i = f2fs_kmem_cache_alloc(free_nid_slab, GFP_NOFS);
+	i->nid = nid;
+	i->state = NID_NEW;
+
+	if (radix_tree_preload(GFP_NOFS))
+		goto err;
+
+	spin_lock(&nm_i->nid_list_lock);
+
 	if (build) {
-		/* do not add allocated nids */
+		/*
+		 *   Thread A             Thread B
+		 *  - f2fs_create
+		 *   - f2fs_new_inode
+		 *    - alloc_nid
+		 *     - __insert_nid_to_list(ALLOC_NID_LIST)
+		 *                     - f2fs_balance_fs_bg
+		 *                      - build_free_nids
+		 *                       - __build_free_nids
+		 *                        - scan_nat_page
+		 *                         - add_free_nid
+		 *                          - __lookup_nat_cache
+		 *  - f2fs_add_link
+		 *   - init_inode_metadata
+		 *    - new_inode_page
+		 *     - new_node_page
+		 *      - set_node_addr
+		 *  - alloc_nid_done
+		 *   - __remove_nid_from_list(ALLOC_NID_LIST)
+		 *                         - __insert_nid_to_list(FREE_NID_LIST)
+		 */
 		ne = __lookup_nat_cache(nm_i, nid);
 		if (ne && (!get_nat_flag(ne, IS_CHECKPOINTED) ||
 				nat_get_blkaddr(ne) != NULL_ADDR))
-			return false;
-	}
-
-	i = f2fs_kmem_cache_alloc(free_nid_slab, GFP_NOFS);
-	i->nid = nid;
-	i->state = NID_NEW;
-
-	if (radix_tree_preload(GFP_NOFS)) {
-		kmem_cache_free(free_nid_slab, i);
-		return true;
-	}
-
-	spin_lock(&nm_i->nid_list_lock);
+			goto err_out;
+
+		e = __lookup_free_nid_list(nm_i, nid);
+		if (e) {
+			if (e->state == NID_NEW)
+				ret = true;
+			goto err_out;
+		}
+	}
+	ret = true;
 	err = __insert_nid_to_list(sbi, i, FREE_NID_LIST, true);
+err_out:
 	spin_unlock(&nm_i->nid_list_lock);
 	radix_tree_preload_end();
-	if (err) {
+err:
+	if (err)
 		kmem_cache_free(free_nid_slab, i);
-		return true;
-	}
-	return true;
+	return ret;
 }
 
 static void remove_free_nid(struct f2fs_sb_info *sbi, nid_t nid)
```
