# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3011_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3011_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 303-343 of the vulnerable file.

		en = rb_entry(node, struct extent_node, rb_node);
		__release_extent_node(sbi, et, en);
		node = next;
	}

	return count - atomic_read(&et->node_cnt);
}

static void __drop_largest_extent(struct inode *inode,
					pgoff_t fofs, unsigned int len)
{
	struct extent_info *largest = &F2FS_I(inode)->extent_tree->largest;

	if (fofs < largest->fofs + largest->len && fofs + len > largest->fofs) {
		largest->len = 0;
		f2fs_mark_inode_dirty_sync(inode, true);
	}
}

/* return true, if inode page is changed */
bool f2fs_init_extent_tree(struct inode *inode, struct f2fs_extent *i_ext)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct extent_tree *et;
	struct extent_node *en;
	struct extent_info ei;

	if (!f2fs_may_extent_tree(inode)) {
		/* drop largest extent */
		if (i_ext && i_ext->len) {
			i_ext->len = 0;
			return true;
		}
		return false;
	}

	et = __grab_extent_tree(inode);

	if (!i_ext || !i_ext->len)
		return false;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -320,7 +320,7 @@
 }
 
 /* return true, if inode page is changed */
-bool f2fs_init_extent_tree(struct inode *inode, struct f2fs_extent *i_ext)
+static bool __f2fs_init_extent_tree(struct inode *inode, struct f2fs_extent *i_ext)
 {
 	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
 	struct extent_tree *et;
@@ -356,6 +356,16 @@
 out:
 	write_unlock(&et->lock);
 	return false;
+}
+
+bool f2fs_init_extent_tree(struct inode *inode, struct f2fs_extent *i_ext)
+{
+	bool ret =  __f2fs_init_extent_tree(inode, i_ext);
+
+	if (!F2FS_I(inode)->extent_tree)
+		set_inode_flag(inode, FI_NO_EXTENT);
+
+	return ret;
 }
 
 static bool f2fs_lookup_extent_tree(struct inode *inode, pgoff_t pgofs,
```
