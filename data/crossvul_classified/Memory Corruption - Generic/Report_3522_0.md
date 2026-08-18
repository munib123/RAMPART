# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3522_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3522_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-33 of the vulnerable file.

/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/gfs2_ondisk.h>
#include <linux/crc32.h>

#include "gfs2.h"
#include "incore.h"
#include "bmap.h"
#include "glock.h"
#include "inode.h"
#include "meta_io.h"
#include "quota.h"
#include "rgrp.h"
#include "super.h"
#include "trans.h"
#include "dir.h"
#include "util.h"
#include "trace_gfs2.h"

/* This doesn't need to be that large as max 64 bit pointers in a 4k
 * block is 512, so __u16 is fine for that. It saves stack space to
 * keep it small.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,7 @@
 #include <linux/spinlock.h>
 #include <linux/completion.h>
 #include <linux/buffer_head.h>
+#include <linux/blkdev.h>
 #include <linux/gfs2_ondisk.h>
 #include <linux/crc32.h>
 
@@ -427,12 +428,14 @@
 {
 	struct gfs2_inode *ip = GFS2_I(inode);
 	struct gfs2_sbd *sdp = GFS2_SB(inode);
+	struct super_block *sb = sdp->sd_vfs;
 	struct buffer_head *dibh = mp->mp_bh[0];
 	u64 bn, dblock = 0;
 	unsigned n, i, blks, alloced = 0, iblks = 0, branch_start = 0;
 	unsigned dblks = 0;
 	unsigned ptrs_per_blk;
 	const unsigned end_of_metadata = height - 1;
+	int ret;
 	int eob = 0;
 	enum alloc_state state;
 	__be64 *ptr;
@@ -535,6 +538,15 @@
 			dblock = bn;
 			while (n-- > 0)
 				*ptr++ = cpu_to_be64(bn++);
+			if (buffer_zeronew(bh_map)) {
+				ret = sb_issue_zeroout(sb, dblock, dblks,
+						       GFP_NOFS);
+				if (ret) {
+					fs_err(sdp,
+					       "Failed to zero data buffers\n");
+					clear_buffer_zeronew(bh_map);
+				}
+			}
 			break;
 		}
 	} while ((state != ALLOC_DATA) || !dblock);
```
