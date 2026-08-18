# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5283_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5283_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 401-441 of the vulnerable file.

			now = php_stream_tell(fp);
			pefree(entry.filename, entry.is_persistent);
			sigfile = php_stream_fopen_tmpfile();
			if (!sigfile) {
				PHAR_ZIP_FAIL("couldn't open temporary file");
			}

			php_stream_seek(fp, 0, SEEK_SET);
			/* copy file contents + local headers and zip comment, if any, to be hashed for signature */
			php_stream_copy_to_stream_ex(fp, sigfile, entry.header_offset, NULL);
			/* seek to central directory */
			php_stream_seek(fp, PHAR_GET_32(locator.cdir_offset), SEEK_SET);
			/* copy central directory header */
			php_stream_copy_to_stream_ex(fp, sigfile, beforeus - PHAR_GET_32(locator.cdir_offset), NULL);
			if (metadata) {
				php_stream_write(sigfile, metadata, PHAR_GET_16(locator.comment_len));
			}
			php_stream_seek(fp, sizeof(phar_zip_file_header) + entry.header_offset + entry.filename_len + PHAR_GET_16(zipentry.extra_len), SEEK_SET);
			sig = (char *) emalloc(entry.uncompressed_filesize);
			read = php_stream_read(fp, sig, entry.uncompressed_filesize);
			if (read != entry.uncompressed_filesize) {
				php_stream_close(sigfile);
				efree(sig);
				PHAR_ZIP_FAIL("signature cannot be read");
			}
			mydata->sig_flags = PHAR_GET_32(sig);
			if (FAILURE == phar_verify_signature(sigfile, php_stream_tell(sigfile), mydata->sig_flags, sig + 8, entry.uncompressed_filesize - 8, fname, &mydata->signature, &mydata->sig_len, error)) {
				efree(sig);
				if (error) {
					char *save;
					php_stream_close(sigfile);
					spprintf(&save, 4096, "signature cannot be verified: %s", *error);
					efree(*error);
					PHAR_ZIP_FAIL_FREE(save, save);
				} else {
					php_stream_close(sigfile);
					PHAR_ZIP_FAIL("signature cannot be verified");
				}
			}
			php_stream_close(sigfile);
			efree(sig);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -418,7 +418,7 @@
 			php_stream_seek(fp, sizeof(phar_zip_file_header) + entry.header_offset + entry.filename_len + PHAR_GET_16(zipentry.extra_len), SEEK_SET);
 			sig = (char *) emalloc(entry.uncompressed_filesize);
 			read = php_stream_read(fp, sig, entry.uncompressed_filesize);
-			if (read != entry.uncompressed_filesize) {
+			if (read != entry.uncompressed_filesize || read <= 8) {
 				php_stream_close(sigfile);
 				efree(sig);
 				PHAR_ZIP_FAIL("signature cannot be read");
```
