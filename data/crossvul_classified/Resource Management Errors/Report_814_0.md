# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 814_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `814_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 2734-2774 of the vulnerable file.

			return (ARCHIVE_WARN);
		}
	}

	return (ARCHIVE_OK);
}

static int
archive_read_format_zip_cleanup(struct archive_read *a)
{
	struct zip *zip;
	struct zip_entry *zip_entry, *next_zip_entry;

	zip = (struct zip *)(a->format->data);

#ifdef HAVE_ZLIB_H
	if (zip->stream_valid)
		inflateEnd(&zip->stream);
#endif

#if HAVA_LZMA_H && HAVE_LIBLZMA
    if (zip->zipx_lzma_valid) {
		lzma_end(&zip->zipx_lzma_stream);
	}
#endif

#ifdef HAVE_BZLIB_H
	if (zip->bzstream_valid) {
		BZ2_bzDecompressEnd(&zip->bzstream);
	}
#endif

	free(zip->uncompressed_buffer);

	if (zip->ppmd8_valid)
		__archive_ppmd8_functions.Ppmd8_Free(&zip->ppmd8);

	if (zip->zip_entries) {
		zip_entry = zip->zip_entries;
		while (zip_entry != NULL) {
			next_zip_entry = zip_entry->next;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2751,7 +2751,7 @@
 		inflateEnd(&zip->stream);
 #endif
 
-#if HAVA_LZMA_H && HAVE_LIBLZMA
+#if HAVE_LZMA_H && HAVE_LIBLZMA
     if (zip->zipx_lzma_valid) {
 		lzma_end(&zip->zipx_lzma_stream);
 	}
```
