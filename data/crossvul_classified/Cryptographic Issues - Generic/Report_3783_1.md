# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 3783_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3783_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 196-236 of the vulnerable file.

{
	int ret;
	struct btrfs_key key;
	int ins_len = mod < 0 ? -1 : 0;
	int cow = mod != 0;

	key.objectid = dir;
	btrfs_set_key_type(&key, BTRFS_DIR_ITEM_KEY);

	key.offset = btrfs_name_hash(name, name_len);

	ret = btrfs_search_slot(trans, root, &key, path, ins_len, cow);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret > 0)
		return NULL;

	return btrfs_match_dir_item_name(root, path, name, name_len);
}

/*
 * lookup a directory item based on index.  'dir' is the objectid
 * we're searching in, and 'mod' tells us if you plan on deleting the
 * item (use mod < 0) or changing the options (use mod > 0)
 *
 * The name is used to make sure the index really points to the name you were
 * looking for.
 */
struct btrfs_dir_item *
btrfs_lookup_dir_index_item(struct btrfs_trans_handle *trans,
			    struct btrfs_root *root,
			    struct btrfs_path *path, u64 dir,
			    u64 objectid, const char *name, int name_len,
			    int mod)
{
	int ret;
	struct btrfs_key key;
	int ins_len = mod < 0 ? -1 : 0;
	int cow = mod != 0;

	key.objectid = dir;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -213,6 +213,65 @@
 	return btrfs_match_dir_item_name(root, path, name, name_len);
 }
 
+int btrfs_check_dir_item_collision(struct btrfs_root *root, u64 dir,
+				   const char *name, int name_len)
+{
+	int ret;
+	struct btrfs_key key;
+	struct btrfs_dir_item *di;
+	int data_size;
+	struct extent_buffer *leaf;
+	int slot;
+	struct btrfs_path *path;
+
+
+	path = btrfs_alloc_path();
+	if (!path)
+		return -ENOMEM;
+
+	key.objectid = dir;
+	btrfs_set_key_type(&key, BTRFS_DIR_ITEM_KEY);
+	key.offset = btrfs_name_hash(name, name_len);
+
+	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
+
+	/* return back any errors */
+	if (ret < 0)
+		goto out;
+
+	/* nothing found, we're safe */
+	if (ret > 0) {
+		ret = 0;
+		goto out;
+	}
+
+	/* we found an item, look for our name in the item */
+	di = btrfs_match_dir_item_name(root, path, name, name_len);
+	if (di) {
+		/* our exact name was found */
+		ret = -EEXIST;
+		goto out;
+	}
+
+	/*
+	 * see if there is room in the item to insert this
+	 * name
+	 */
+	data_size = sizeof(*di) + name_len + sizeof(struct btrfs_item);
+	leaf = path->nodes[0];
+	slot = path->slots[0];
+	if (data_size + btrfs_item_size_nr(leaf, slot) +
+	    sizeof(struct btrfs_item) > BTRFS_LEAF_DATA_SIZE(root)) {
+		ret = -EOVERFLOW;
+	} else {
+		/* plenty of insertion room */
+		ret = 0;
+	}
+out:
+	btrfs_free_path(path);
+	return ret;
+}
+
 /*
  * lookup a directory item based on index.  'dir' is the objectid
  * we're searching in, and 'mod' tells us if you plan on deleting the
```
