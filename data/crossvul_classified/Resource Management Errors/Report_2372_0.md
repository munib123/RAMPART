# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2372_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2372_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

#include "rock.h"

/*
 * These functions are designed to read the system areas of a directory record
 * and extract relevant information.  There are different functions provided
 * depending upon what information we need at the time.  One function fills
 * out an inode structure, a second one extracts a filename, a third one
 * returns a symbolic link name, and a fourth one returns the extent number
 * for the file.
 */

#define SIG(A,B) ((A) | ((B) << 8))	/* isonum_721() */

struct rock_state {
	void *buffer;
	unsigned char *chr;
	int len;
	int cont_size;
	int cont_extent;
	int cont_offset;
	struct inode *inode;
};

/*
 * This is a way of ensuring that we have something in the system
 * use fields that is compatible with Rock Ridge.  Return zero on success.
 */

static int check_sp(struct rock_ridge *rr, struct inode *inode)
{
	if (rr->u.SP.magic[0] != 0xbe)
		return -1;
	if (rr->u.SP.magic[1] != 0xef)
		return -1;
	ISOFS_SB(inode->i_sb)->s_rock_offset = rr->u.SP.skip;
	return 0;
}

static void setup_rock_ridge(struct iso_directory_record *de,
			struct inode *inode, struct rock_state *rs)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,7 @@
 	int cont_size;
 	int cont_extent;
 	int cont_offset;
+	int cont_loops;
 	struct inode *inode;
 };
 
@@ -72,6 +73,9 @@
 	memset(rs, 0, sizeof(*rs));
 	rs->inode = inode;
 }
+
+/* Maximum number of Rock Ridge continuation entries */
+#define RR_MAX_CE_ENTRIES 32
 
 /*
  * Returns 0 if the caller should continue scanning, 1 if the scan must end
@@ -105,6 +109,8 @@
 			goto out;
 		}
 		ret = -EIO;
+		if (++rs->cont_loops >= RR_MAX_CE_ENTRIES)
+			goto out;
 		bh = sb_bread(rs->inode->i_sb, rs->cont_extent);
 		if (bh) {
 			memcpy(rs->buffer, bh->b_data + rs->cont_offset,
```
