# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2415_2
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2415_2`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 13-54 of the vulnerable file.

 *  (C) 1998-2001 Ben Fennema
 *  (C) 1999 Stelias Computing Inc
 *
 * HISTORY
 *
 *  04/16/99 blf  Created.
 *
 */

#include "udfdecl.h"
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include "udf_i.h"

static void udf_pc_to_char(struct super_block *sb, unsigned char *from,
			   int fromlen, unsigned char *to)
{
	struct pathComponent *pc;
	int elen = 0;
	unsigned char *p = to;

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
			p = to;
			*p++ = '/';
			break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,13 +30,16 @@
 #include <linux/buffer_head.h>
 #include "udf_i.h"
 
-static void udf_pc_to_char(struct super_block *sb, unsigned char *from,
-			   int fromlen, unsigned char *to)
+static int udf_pc_to_char(struct super_block *sb, unsigned char *from,
+			  int fromlen, unsigned char *to, int tolen)
 {
 	struct pathComponent *pc;
 	int elen = 0;
+	int comp_len;
 	unsigned char *p = to;
 
+	/* Reserve one byte for terminating \0 */
+	tolen--;
 	while (elen < fromlen) {
 		pc = (struct pathComponent *)(from + elen);
 		switch (pc->componentType) {
@@ -49,22 +52,37 @@
 				break;
 			/* Fall through */
 		case 2:
+			if (tolen == 0)
+				return -ENAMETOOLONG;
 			p = to;
 			*p++ = '/';
+			tolen--;
 			break;
 		case 3:
+			if (tolen < 3)
+				return -ENAMETOOLONG;
 			memcpy(p, "../", 3);
 			p += 3;
+			tolen -= 3;
 			break;
 		case 4:
+			if (tolen < 2)
+				return -ENAMETOOLONG;
 			memcpy(p, "./", 2);
 			p += 2;
+			tolen -= 2;
 			/* that would be . - just ignore */
 			break;
 		case 5:
-			p += udf_get_filename(sb, pc->componentIdent, p,
-					      pc->lengthComponentIdent);
+			comp_len = udf_get_filename(sb, pc->componentIdent,
+						    pc->lengthComponentIdent,
+						    p, tolen);
+			p += comp_len;
+			tolen -= comp_len;
+			if (tolen == 0)
+				return -ENAMETOOLONG;
 			*p++ = '/';
+			tolen--;
 			break;
 		}
 		elen += sizeof(struct pathComponent) + pc->lengthComponentIdent;
@@ -73,6 +91,7 @@
 		p[-1] = '\0';
 	else
 		p[0] = '\0';
+	return 0;
 }
 
 static int udf_symlink_filler(struct file *file, struct page *page)
@@ -108,8 +127,10 @@
 		symlink = bh->b_data;
 	}
 
-	udf_pc_to_char(inode->i_sb, symlink, inode->i_size, p);
+	err = udf_pc_to_char(inode->i_sb, symlink, inode->i_size, p, PAGE_SIZE);
 	brelse(bh);
+	if (err)
+		goto out_unlock_inode;
 
 	up_read(&iinfo->i_data_sem);
 	SetPageUptodate(page);
```
