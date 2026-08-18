# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 706_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `706_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2947-2993 of the vulnerable file.

	zip->pack_stream_remaining = 0;
	zip->pack_stream_index = 0;
	zip->folder_outbytes_remaining = 0;
	zip->uncompressed_buffer_bytes_remaining = 0;
	zip->pack_stream_bytes_unconsumed = 0;
	zip->header_is_being_read = 0;

	return (ARCHIVE_OK);
}

static ssize_t
get_uncompressed_data(struct archive_read *a, const void **buff, size_t size,
    size_t minimum)
{
	struct _7zip *zip = (struct _7zip *)a->format->data;
	ssize_t bytes_avail;

	if (zip->codec == _7Z_COPY && zip->codec2 == (unsigned long)-1) {
		/* Copy mode. */

		/*
		 * Note: '1' here is a performance optimization.
		 * Recall that the decompression layer returns a count of
		 * available bytes; asking for more than that forces the
		 * decompressor to combine reads by copying data.
		 */
		*buff = __archive_read_ahead(a, 1, &bytes_avail);
		if (bytes_avail <= 0) {
			archive_set_error(&a->archive,
			    ARCHIVE_ERRNO_FILE_FORMAT,
			    "Truncated 7-Zip file data");
			return (ARCHIVE_FATAL);
		}
		if ((size_t)bytes_avail >
		    zip->uncompressed_buffer_bytes_remaining)
			bytes_avail = (ssize_t)
			    zip->uncompressed_buffer_bytes_remaining;
		if ((size_t)bytes_avail > size)
			bytes_avail = (ssize_t)size;

		zip->pack_stream_bytes_unconsumed = bytes_avail;
	} else if (zip->uncompressed_buffer_pointer == NULL) {
		/* Decompression has failed. */
		archive_set_error(&(a->archive),
		    ARCHIVE_ERRNO_MISC, "Damaged 7-Zip archive");
		return (ARCHIVE_FATAL);
	} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2964,13 +2964,7 @@
 	if (zip->codec == _7Z_COPY && zip->codec2 == (unsigned long)-1) {
 		/* Copy mode. */
 
-		/*
-		 * Note: '1' here is a performance optimization.
-		 * Recall that the decompression layer returns a count of
-		 * available bytes; asking for more than that forces the
-		 * decompressor to combine reads by copying data.
-		 */
-		*buff = __archive_read_ahead(a, 1, &bytes_avail);
+		*buff = __archive_read_ahead(a, minimum, &bytes_avail);
 		if (bytes_avail <= 0) {
 			archive_set_error(&a->archive,
 			    ARCHIVE_ERRNO_FILE_FORMAT,
```
