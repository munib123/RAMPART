# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3522_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3522_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.

	u32 rd_length;			/* length of rgrp header in fs blocks */
	u32 rd_data;			/* num of data blocks in rgrp */
	u32 rd_bitbytes;		/* number of bytes in data bitmaps */
	u32 rd_free;
	u32 rd_free_clone;
	u32 rd_dinodes;
	u64 rd_igeneration;
	struct gfs2_bitmap *rd_bits;
	struct gfs2_sbd *rd_sbd;
	u32 rd_last_alloc;
	u32 rd_flags;
#define GFS2_RDF_CHECK		0x10000000 /* check for unlinked inodes */
#define GFS2_RDF_UPTODATE	0x20000000 /* rg is up to date */
#define GFS2_RDF_ERROR		0x40000000 /* error in rg */
#define GFS2_RDF_MASK		0xf0000000 /* mask for internal flags */
};

enum gfs2_state_bits {
	BH_Pinned = BH_PrivateStart,
	BH_Escaped = BH_PrivateStart + 1,
};

BUFFER_FNS(Pinned, pinned)
TAS_BUFFER_FNS(Pinned, pinned)
BUFFER_FNS(Escaped, escaped)
TAS_BUFFER_FNS(Escaped, escaped)

struct gfs2_bufdata {
	struct buffer_head *bd_bh;
	struct gfs2_glock *bd_gl;

	union {
		struct list_head list_tr;
		u64 blkno;
	} u;
#define bd_list_tr u.list_tr
#define bd_blkno u.blkno

	struct gfs2_log_element bd_le;

	struct gfs2_ail *bd_ail;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,12 +103,15 @@
 enum gfs2_state_bits {
 	BH_Pinned = BH_PrivateStart,
 	BH_Escaped = BH_PrivateStart + 1,
+	BH_Zeronew = BH_PrivateStart + 2,
 };
 
 BUFFER_FNS(Pinned, pinned)
 TAS_BUFFER_FNS(Pinned, pinned)
 BUFFER_FNS(Escaped, escaped)
 TAS_BUFFER_FNS(Escaped, escaped)
+BUFFER_FNS(Zeronew, zeronew)
+TAS_BUFFER_FNS(Zeronew, zeronew)
 
 struct gfs2_bufdata {
 	struct buffer_head *bd_bh;
```
