# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4904_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4904_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2761-2801 of the vulnerable file.

	}
	filename_length = archive_le16dec(p + 26);
	extra_length = archive_le16dec(p + 28);

	return (30 + filename_length + extra_length);
}

static int
zip_read_mac_metadata(struct archive_read *a, struct archive_entry *entry,
    struct zip_entry *rsrc)
{
	struct zip *zip = (struct zip *)a->format->data;
	unsigned char *metadata, *mp;
	int64_t offset = archive_filter_bytes(&a->archive, 0);
	size_t remaining_bytes, metadata_bytes;
	ssize_t hsize;
	int ret = ARCHIVE_OK, eof;

	switch(rsrc->compression) {
	case 0:  /* No compression. */
#ifdef HAVE_ZLIB_H
	case 8: /* Deflate compression. */
#endif
		break;
	default: /* Unsupported compression. */
		/* Return a warning. */
		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
		    "Unsupported ZIP compression method (%s)",
		    compression_name(rsrc->compression));
		/* We can't decompress this entry, but we will
		 * be able to skip() it and try the next entry. */
		return (ARCHIVE_WARN);
	}

	if (rsrc->uncompressed_size > (4 * 1024 * 1024)) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
		    "Mac metadata is too large: %jd > 4M bytes",
		    (intmax_t)rsrc->uncompressed_size);
		return (ARCHIVE_WARN);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2778,6 +2778,11 @@
 
 	switch(rsrc->compression) {
 	case 0:  /* No compression. */
+		if (rsrc->uncompressed_size != rsrc->compressed_size) {
+			archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+			    "Malformed OS X metadata entry: inconsistent size");
+			return (ARCHIVE_FATAL);
+		}
 #ifdef HAVE_ZLIB_H
 	case 8: /* Deflate compression. */
 #endif
@@ -2798,6 +2803,12 @@
 		    (intmax_t)rsrc->uncompressed_size);
 		return (ARCHIVE_WARN);
 	}
+	if (rsrc->compressed_size > (4 * 1024 * 1024)) {
+		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+		    "Mac metadata is too large: %jd > 4M bytes",
+		    (intmax_t)rsrc->compressed_size);
+		return (ARCHIVE_WARN);
+	}
 
 	metadata = malloc((size_t)rsrc->uncompressed_size);
 	if (metadata == NULL) {
@@ -2836,6 +2847,8 @@
 			bytes_avail = remaining_bytes;
 		switch(rsrc->compression) {
 		case 0:  /* No compression. */
+			if ((size_t)bytes_avail > metadata_bytes)
+				bytes_avail = metadata_bytes;
 			memcpy(mp, p, bytes_avail);
 			bytes_used = (size_t)bytes_avail;
 			metadata_bytes -= bytes_used;
```
