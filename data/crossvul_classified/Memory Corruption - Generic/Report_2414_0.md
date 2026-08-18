# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2414_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2414_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.

#include <linux/fs.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include "udf_i.h"

static int udf_pc_to_char(struct super_block *sb, unsigned char *from,
			  int fromlen, unsigned char *to, int tolen)
{
	struct pathComponent *pc;
	int elen = 0;
	int comp_len;
	unsigned char *p = to;

	/* Reserve one byte for terminating \0 */
	tolen--;
	while (elen < fromlen) {
		pc = (struct pathComponent *)(from + elen);
		switch (pc->componentType) {
		case 1:
			/*
			 * Symlink points to some place which should be agreed
 			 * upon between originator and receiver of the media. Ignore.
			 */
			if (pc->lengthComponentIdent > 0)
				break;
			/* Fall through */
		case 2:
			if (tolen == 0)
				return -ENAMETOOLONG;
			p = to;
			*p++ = '/';
			tolen--;
			break;
		case 3:
			if (tolen < 3)
				return -ENAMETOOLONG;
			memcpy(p, "../", 3);
			p += 3;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,14 +42,17 @@
 	tolen--;
 	while (elen < fromlen) {
 		pc = (struct pathComponent *)(from + elen);
+		elen += sizeof(struct pathComponent);
 		switch (pc->componentType) {
 		case 1:
 			/*
 			 * Symlink points to some place which should be agreed
  			 * upon between originator and receiver of the media. Ignore.
 			 */
-			if (pc->lengthComponentIdent > 0)
+			if (pc->lengthComponentIdent > 0) {
+				elen += pc->lengthComponentIdent;
 				break;
+			}
 			/* Fall through */
 		case 2:
 			if (tolen == 0)
@@ -74,6 +77,9 @@
 			/* that would be . - just ignore */
 			break;
 		case 5:
+			elen += pc->lengthComponentIdent;
+			if (elen > fromlen)
+				return -EIO;
 			comp_len = udf_get_filename(sb, pc->componentIdent,
 						    pc->lengthComponentIdent,
 						    p, tolen);
@@ -85,7 +91,6 @@
 			tolen--;
 			break;
 		}
-		elen += sizeof(struct pathComponent) + pc->lengthComponentIdent;
 	}
 	if (p > to + 1)
 		p[-1] = '\0';
```
