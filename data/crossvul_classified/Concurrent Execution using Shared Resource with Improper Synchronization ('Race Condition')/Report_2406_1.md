# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2406_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2406_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 590-630 of the vulnerable file.

 */
struct btrfs_path {
	struct extent_buffer *nodes[BTRFS_MAX_LEVEL];
	int slots[BTRFS_MAX_LEVEL];
	/* if there is real range locking, this locks field will change */
	int locks[BTRFS_MAX_LEVEL];
	int reada;
	/* keep some upper locks as we walk down */
	int lowest_level;

	/*
	 * set by btrfs_split_item, tells search_slot to keep all locks
	 * and to force calls to keep space in the nodes
	 */
	unsigned int search_for_split:1;
	unsigned int keep_locks:1;
	unsigned int skip_locking:1;
	unsigned int leave_spinning:1;
	unsigned int search_commit_root:1;
	unsigned int need_commit_sem:1;
};

/*
 * items in the extent btree are used to record the objectid of the
 * owner of the block and the number of references
 */

struct btrfs_extent_item {
	__le64 refs;
	__le64 generation;
	__le64 flags;
} __attribute__ ((__packed__));

struct btrfs_extent_item_v0 {
	__le32 refs;
} __attribute__ ((__packed__));

#define BTRFS_MAX_EXTENT_ITEM_SIZE(r) ((BTRFS_LEAF_DATA_SIZE(r) >> 4) - \
					sizeof(struct btrfs_item))

#define BTRFS_EXTENT_FLAG_DATA		(1ULL << 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -607,6 +607,7 @@
 	unsigned int leave_spinning:1;
 	unsigned int search_commit_root:1;
 	unsigned int need_commit_sem:1;
+	unsigned int skip_release_on_error:1;
 };
 
 /*
@@ -3690,6 +3691,10 @@
 int verify_dir_item(struct btrfs_root *root,
 		    struct extent_buffer *leaf,
 		    struct btrfs_dir_item *dir_item);
+struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_root *root,
+						 struct btrfs_path *path,
+						 const char *name,
+						 int name_len);
 
 /* orphan.c */
 int btrfs_insert_orphan_item(struct btrfs_trans_handle *trans,
```
