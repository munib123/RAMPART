# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4823_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4823_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1038-1078 of the vulnerable file.


	/* set up our manifest */
	zend_hash_init(&mydata->manifest, manifest_count,
		zend_get_hash_value, destroy_phar_manifest_entry, (zend_bool)mydata->is_persistent);
	zend_hash_init(&mydata->mounted_dirs, 5,
		zend_get_hash_value, NULL, (zend_bool)mydata->is_persistent);
	zend_hash_init(&mydata->virtual_dirs, manifest_count * 2,
		zend_get_hash_value, NULL, (zend_bool)mydata->is_persistent);
	mydata->fname = pestrndup(fname, fname_len, mydata->is_persistent);
#ifdef PHP_WIN32
	phar_unixify_path_separators(mydata->fname, fname_len);
#endif
	mydata->fname_len = fname_len;
	offset = halt_offset + manifest_len + 4;
	memset(&entry, 0, sizeof(phar_entry_info));
	entry.phar = mydata;
	entry.fp_type = PHAR_FP;
	entry.is_persistent = mydata->is_persistent;

	for (manifest_index = 0; manifest_index < manifest_count; ++manifest_index) {
		if (buffer + 4 > endbuffer) {
			MAPPHAR_FAIL("internal corruption of phar \"%s\" (truncated manifest entry)")
		}

		PHAR_GET_32(buffer, entry.filename_len);

		if (entry.filename_len == 0) {
			MAPPHAR_FAIL("zero-length filename encountered in phar \"%s\"");
		}

		if (entry.is_persistent) {
			entry.manifest_pos = manifest_index;
		}

		if (entry.filename_len + 20 > endbuffer - buffer) {
			MAPPHAR_FAIL("internal corruption of phar \"%s\" (truncated manifest entry)");
		}

		if ((manifest_ver & PHAR_API_VER_MASK) >= PHAR_API_MIN_DIR && buffer[entry.filename_len - 1] == '/') {
			entry.is_dir = 1;
		} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1055,7 +1055,7 @@
 	entry.is_persistent = mydata->is_persistent;
 
 	for (manifest_index = 0; manifest_index < manifest_count; ++manifest_index) {
-		if (buffer + 4 > endbuffer) {
+		if (buffer + 24 > endbuffer) {
 			MAPPHAR_FAIL("internal corruption of phar \"%s\" (truncated manifest entry)")
 		}
 
@@ -1069,7 +1069,7 @@
 			entry.manifest_pos = manifest_index;
 		}
 
-		if (entry.filename_len + 20 > endbuffer - buffer) {
+		if (entry.filename_len > endbuffer - buffer - 20) {
 			MAPPHAR_FAIL("internal corruption of phar \"%s\" (truncated manifest entry)");
 		}
 
```
