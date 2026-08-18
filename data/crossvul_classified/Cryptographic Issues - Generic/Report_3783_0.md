# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 3783_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3783_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 3266-3306 of the vulnerable file.

		      *root, struct btrfs_key *key, struct btrfs_root_item
		      *item);
int __must_check btrfs_update_root(struct btrfs_trans_handle *trans,
				   struct btrfs_root *root,
				   struct btrfs_key *key,
				   struct btrfs_root_item *item);
void btrfs_read_root_item(struct btrfs_root *root,
			 struct extent_buffer *eb, int slot,
			 struct btrfs_root_item *item);
int btrfs_find_last_root(struct btrfs_root *root, u64 objectid, struct
			 btrfs_root_item *item, struct btrfs_key *key);
int btrfs_find_dead_roots(struct btrfs_root *root, u64 objectid);
int btrfs_find_orphan_roots(struct btrfs_root *tree_root);
void btrfs_set_root_node(struct btrfs_root_item *item,
			 struct extent_buffer *node);
void btrfs_check_and_init_root_item(struct btrfs_root_item *item);
void btrfs_update_root_times(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root);

/* dir-item.c */
int btrfs_insert_dir_item(struct btrfs_trans_handle *trans,
			  struct btrfs_root *root, const char *name,
			  int name_len, struct inode *dir,
			  struct btrfs_key *location, u8 type, u64 index);
struct btrfs_dir_item *btrfs_lookup_dir_item(struct btrfs_trans_handle *trans,
					     struct btrfs_root *root,
					     struct btrfs_path *path, u64 dir,
					     const char *name, int name_len,
					     int mod);
struct btrfs_dir_item *
btrfs_lookup_dir_index_item(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root,
			    struct btrfs_path *path, u64 dir,
			    u64 objectid, const char *name, int name_len,
			    int mod);
struct btrfs_dir_item *
btrfs_search_dir_index_item(struct btrfs_root *root,
			    struct btrfs_path *path, u64 dirid,
			    const char *name, int name_len);
struct btrfs_dir_item *btrfs_match_dir_item_name(struct btrfs_root *root,
			      struct btrfs_path *path,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3283,6 +3283,8 @@
 			     struct btrfs_root *root);
 
 /* dir-item.c */
+int btrfs_check_dir_item_collision(struct btrfs_root *root, u64 dir,
+			  const char *name, int name_len);
 int btrfs_insert_dir_item(struct btrfs_trans_handle *trans,
 			  struct btrfs_root *root, const char *name,
 			  int name_len, struct inode *dir,
```
