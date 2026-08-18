# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5181_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5181_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1074-1114 of the vulnerable file.

	return (ARCHIVE_OK);
}

static int
choose_volume(struct archive_read *a, struct iso9660 *iso9660)
{
	struct file_info *file;
	int64_t skipsize;
	struct vd *vd;
	const void *block;
	char seenJoliet;

	vd = &(iso9660->primary);
	if (!iso9660->opt_support_joliet)
		iso9660->seenJoliet = 0;
	if (iso9660->seenJoliet &&
		vd->location > iso9660->joliet.location)
		/* This condition is unlikely; by way of caution. */
		vd = &(iso9660->joliet);

	skipsize = LOGICAL_BLOCK_SIZE * vd->location;
	skipsize = __archive_read_consume(a, skipsize);
	if (skipsize < 0)
		return ((int)skipsize);
	iso9660->current_position = skipsize;

	block = __archive_read_ahead(a, vd->size, NULL);
	if (block == NULL) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Failed to read full block when scanning "
		    "ISO9660 directory list");
		return (ARCHIVE_FATAL);
	}

	/*
	 * While reading Root Directory, flag seenJoliet must be zero to
	 * avoid converting special name 0x00(Current Directory) and
	 * next byte to UCS2.
	 */
	seenJoliet = iso9660->seenJoliet;/* Save flag. */
	iso9660->seenJoliet = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1091,7 +1091,7 @@
 		/* This condition is unlikely; by way of caution. */
 		vd = &(iso9660->joliet);
 
-	skipsize = LOGICAL_BLOCK_SIZE * vd->location;
+	skipsize = LOGICAL_BLOCK_SIZE * (int64_t)vd->location;
 	skipsize = __archive_read_consume(a, skipsize);
 	if (skipsize < 0)
 		return ((int)skipsize);
@@ -1129,7 +1129,7 @@
 	    && iso9660->seenJoliet) {
 		/* Switch reading data from primary to joliet. */
 		vd = &(iso9660->joliet);
-		skipsize = LOGICAL_BLOCK_SIZE * vd->location;
+		skipsize = LOGICAL_BLOCK_SIZE * (int64_t)vd->location;
 		skipsize -= iso9660->current_position;
 		skipsize = __archive_read_consume(a, skipsize);
 		if (skipsize < 0)
```
