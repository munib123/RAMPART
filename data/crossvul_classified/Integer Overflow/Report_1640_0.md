# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1640_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1640_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 133-173 of the vulnerable file.

	if(xattr->full_name == NULL)
		MEM_ERROR();

	memcpy(xattr->full_name, prefix_table[i].prefix, len);
	memcpy(xattr->full_name + len, name, entry->size);
	xattr->full_name[len + entry->size] = '\0';
	xattr->name = xattr->full_name + len;
	xattr->size = entry->size;
	xattr->type = type;

	return 1;
}


/*
 * Read and decompress the xattr id table and the xattr metadata.
 * This is cached in memory for later use by get_xattr()
 */
int read_xattrs_from_disk(int fd, struct squashfs_super_block *sBlk, int flag, long long *table_start)
{
	int res, bytes, i, indexes, index_bytes, ids;
	long long *index, start, end;
	struct squashfs_xattr_table id_table;

	TRACE("read_xattrs_from_disk\n");

	if(sBlk->xattr_id_table_start == SQUASHFS_INVALID_BLK)
		return SQUASHFS_INVALID_BLK;

	/*
	 * Read xattr id table, containing start of xattr metadata and the
	 * number of xattrs in the file system
	 */
	res = read_fs_bytes(fd, sBlk->xattr_id_table_start, sizeof(id_table),
		&id_table);
	if(res == 0)
		return 0;

	SQUASHFS_INSWAP_XATTR_TABLE(&id_table);

	if(flag) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,7 +150,16 @@
  */
 int read_xattrs_from_disk(int fd, struct squashfs_super_block *sBlk, int flag, long long *table_start)
 {
-	int res, bytes, i, indexes, index_bytes, ids;
+	/*
+	 * Note on overflow limits:
+	 * Size of ids (id_table.xattr_ids) is 2^32 (unsigned int)
+	 * Max size of bytes is 2^32*16 or 2^36
+	 * Max indexes is (2^32*16)/8K or 2^23
+	 * Max index_bytes is ((2^32*16)/8K)*8 or 2^26 or 64M
+	 */
+	int res, i, indexes, index_bytes;
+	unsigned int ids;
+	long long bytes;
 	long long *index, start, end;
 	struct squashfs_xattr_table id_table;
 
@@ -170,24 +179,44 @@
 
 	SQUASHFS_INSWAP_XATTR_TABLE(&id_table);
 
-	if(flag) {
-		/*
-		 * id_table.xattr_table_start stores the start of the compressed xattr
-		 * * metadata blocks.  This by definition is also the end of the previous
-		 * filesystem table - the id lookup table.
-		 */
+	/*
+	 * Compute index table values
+	 */
+	ids = id_table.xattr_ids;
+	xattr_table_start = id_table.xattr_table_start;
+	index_bytes = SQUASHFS_XATTR_BLOCK_BYTES((long long) ids);
+	indexes = SQUASHFS_XATTR_BLOCKS((long long) ids);
+
+	/*
+	 * The size of the index table (index_bytes) should match the
+	 * table start and end points
+	 */
+	if(index_bytes != (sBlk->bytes_used - (sBlk->xattr_id_table_start + sizeof(id_table)))) {
+		ERROR("read_xattrs_from_disk: Bad xattr_ids count in super block\n");
+		return 0;
+	}
+
+	/*
+	 * id_table.xattr_table_start stores the start of the compressed xattr
+	 * metadata blocks.  This by definition is also the end of the previous
+	 * filesystem table - the id lookup table.
+	 */
+	if(table_start != NULL)
 		*table_start = id_table.xattr_table_start;
+
+	/*
+	 * If flag is set then return once we've read the above
+	 * table_start.  That value is necessary for sanity checking,
+	 * but we don't actually want to extract the xattrs, and so
+	 * stop here.
+	 */
+	if(flag)
 		return id_table.xattr_ids;
-	}
 
 	/*
 	 * Allocate and read the index to the xattr id table metadata
 	 * blocks
 	 */
-	ids = id_table.xattr_ids;
-	xattr_table_start = id_table.xattr_table_start;
-	index_bytes = SQUASHFS_XATTR_BLOCK_BYTES(ids);
-	indexes = SQUASHFS_XATTR_BLOCKS(ids);
 	index = malloc(index_bytes);
 	if(index == NULL)
 		MEM_ERROR();
@@ -203,7 +232,7 @@
 	 * Allocate enough space for the uncompressed xattr id table, and
 	 * read and decompress it
 	 */
-	bytes = SQUASHFS_XATTR_BYTES(ids);
+	bytes = SQUASHFS_XATTR_BYTES((long long) ids);
 	xattr_ids = malloc(bytes);
 	if(xattr_ids == NULL)
 		MEM_ERROR();
@@ -213,7 +242,7 @@
 					bytes & (SQUASHFS_METADATA_SIZE - 1);
 		int length = read_block(fd, index[i], NULL, expected,
 			((unsigned char *) xattr_ids) +
-			(i * SQUASHFS_METADATA_SIZE));
+			((long long) i * SQUASHFS_METADATA_SIZE));
 		TRACE("Read xattr id table block %d, from 0x%llx, length "
 			"%d\n", i, index[i], length);
 		if(length == 0) {
```
