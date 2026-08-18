# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4685_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4685_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2068-2108 of the vulnerable file.

 *
 * Each <FILE> block contains info about its size, the name of the file it's
 * storing inside, and whether this FILE block is a continuation block of
 * previous archive ('split before'), and is this FILE block should be
 * continued in another archive ('split after'). By parsing the 'split before'
 * and 'split after' flags, we're able to tell if multiple <FILE> base blocks
 * are describing one file, or multiple files (with the same filename, for
 * example).
 *
 * One thing to note is that if we're parsing the first <FILE> block, and
 * we see 'split after' flag, then we need to jump over to another <FILE>
 * block to be able to decompress rest of the data. To do this, we need
 * to skip the <ENDARC> block, then switch to another file, then skip the
 * <magic> block, <MAIN> block, and then we're standing on the proper
 * <FILE> block.
 */

static int process_base_block(struct archive_read* a,
    struct archive_entry* entry)
{
	struct rar5* rar = get_context(a);
	uint32_t hdr_crc, computed_crc;
	size_t raw_hdr_size = 0, hdr_size_len, hdr_size;
	size_t header_id = 0;
	size_t header_flags = 0;
	const uint8_t* p;
	int ret;

	enum HEADER_TYPE {
		HEAD_MARK    = 0x00, HEAD_MAIN  = 0x01, HEAD_FILE   = 0x02,
		HEAD_SERVICE = 0x03, HEAD_CRYPT = 0x04, HEAD_ENDARC = 0x05,
		HEAD_UNKNOWN = 0xff,
	};

	/* Skip any unprocessed data for this file. */
	ret = skip_unprocessed_bytes(a);
	if(ret != ARCHIVE_OK)
		return ret;

	/* Read the expected CRC32 checksum. */
	if(!read_u32(a, &hdr_crc)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2085,6 +2085,8 @@
 static int process_base_block(struct archive_read* a,
     struct archive_entry* entry)
 {
+	const size_t SMALLEST_RAR5_BLOCK_SIZE = 3;
+
 	struct rar5* rar = get_context(a);
 	uint32_t hdr_crc, computed_crc;
 	size_t raw_hdr_size = 0, hdr_size_len, hdr_size;
@@ -2114,15 +2116,26 @@
 		return ARCHIVE_EOF;
 	}
 
+	hdr_size = raw_hdr_size + hdr_size_len;
+
 	/* Sanity check, maximum header size for RAR5 is 2MB. */
-	if(raw_hdr_size > (2 * 1024 * 1024)) {
+	if(hdr_size > (2 * 1024 * 1024)) {
 		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
 		    "Base block header is too large");
 
 		return ARCHIVE_FATAL;
 	}
 
-	hdr_size = raw_hdr_size + hdr_size_len;
+	/* Additional sanity checks to weed out invalid files. */
+	if(raw_hdr_size == 0 || hdr_size_len == 0 ||
+		hdr_size < SMALLEST_RAR5_BLOCK_SIZE)
+	{
+		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+		    "Too small block encountered (%ld bytes)",
+		    raw_hdr_size);
+
+		return ARCHIVE_FATAL;
+	}
 
 	/* Read the whole header data into memory, maximum memory use here is
 	 * 2MB. */
```
