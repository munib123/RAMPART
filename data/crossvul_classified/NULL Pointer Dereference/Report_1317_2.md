# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1317_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1317_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1011-1052 of the vulnerable file.


DECLARE_EVENT_CLASS(f2fs__submit_page_bio,

	TP_PROTO(struct page *page, struct f2fs_io_info *fio),

	TP_ARGS(page, fio),

	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(ino_t, ino)
		__field(pgoff_t, index)
		__field(block_t, old_blkaddr)
		__field(block_t, new_blkaddr)
		__field(int, op)
		__field(int, op_flags)
		__field(int, temp)
		__field(int, type)
	),

	TP_fast_assign(
		__entry->dev		= page->mapping->host->i_sb->s_dev;
		__entry->ino		= page->mapping->host->i_ino;
		__entry->index		= page->index;
		__entry->old_blkaddr	= fio->old_blkaddr;
		__entry->new_blkaddr	= fio->new_blkaddr;
		__entry->op		= fio->op;
		__entry->op_flags	= fio->op_flags;
		__entry->temp		= fio->temp;
		__entry->type		= fio->type;
	),

	TP_printk("dev = (%d,%d), ino = %lu, page_index = 0x%lx, "
		"oldaddr = 0x%llx, newaddr = 0x%llx, rw = %s(%s), type = %s_%s",
		show_dev_ino(__entry),
		(unsigned long)__entry->index,
		(unsigned long long)__entry->old_blkaddr,
		(unsigned long long)__entry->new_blkaddr,
		show_bio_type(__entry->op, __entry->op_flags),
		show_block_temp(__entry->temp),
		show_block_type(__entry->type))
);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1028,8 +1028,8 @@
 	),
 
 	TP_fast_assign(
-		__entry->dev		= page->mapping->host->i_sb->s_dev;
-		__entry->ino		= page->mapping->host->i_ino;
+		__entry->dev		= page_file_mapping(page)->host->i_sb->s_dev;
+		__entry->ino		= page_file_mapping(page)->host->i_ino;
 		__entry->index		= page->index;
 		__entry->old_blkaddr	= fio->old_blkaddr;
 		__entry->new_blkaddr	= fio->new_blkaddr;
@@ -1216,10 +1216,11 @@
 	),
 
 	TP_fast_assign(
-		__entry->dev	= page->mapping->host->i_sb->s_dev;
-		__entry->ino	= page->mapping->host->i_ino;
+		__entry->dev	= page_file_mapping(page)->host->i_sb->s_dev;
+		__entry->ino	= page_file_mapping(page)->host->i_ino;
 		__entry->type	= type;
-		__entry->dir	= S_ISDIR(page->mapping->host->i_mode);
+		__entry->dir	=
+			S_ISDIR(page_file_mapping(page)->host->i_mode);
 		__entry->index	= page->index;
 		__entry->dirty	= PageDirty(page);
 		__entry->uptodate = PageUptodate(page);
```
