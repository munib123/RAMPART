# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2769_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2769_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 830-863 of the vulnerable file.


    size = _zip_buffer_get_64(buffer);
    offset = _zip_buffer_get_64(buffer);

    if (!_zip_buffer_ok(buffer)) {
        zip_error_set(error, ZIP_ER_INTERNAL, 0);
        if (free_buffer) {
            _zip_buffer_free(buffer);
        }
        return NULL;
    }

    if (free_buffer) {
        _zip_buffer_free(buffer);
    }

    if (offset > ZIP_INT64_MAX || offset+size < offset) {
        zip_error_set(error, ZIP_ER_SEEK, EFBIG);
        return NULL;
    }
    if ((flags & ZIP_CHECKCONS) && offset+size != eocd_offset) {
	zip_error_set(error, ZIP_ER_INCONS, 0);
	return NULL;
    }

    if ((cd=_zip_cdir_new(nentry, error)) == NULL)
	return NULL;

    cd->is_zip64 = true;
    cd->size = size;
    cd->offset = offset;

    return cd;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -847,7 +847,12 @@
         zip_error_set(error, ZIP_ER_SEEK, EFBIG);
         return NULL;
     }
-    if ((flags & ZIP_CHECKCONS) && offset+size != eocd_offset) {
+    if (offset+size > buf_offset + eocd_offset) {
+	/* cdir spans past EOCD record */
+	zip_error_set(error, ZIP_ER_INCONS, 0);
+	return NULL;
+    }
+    if ((flags & ZIP_CHECKCONS) && offset+size != buf_offset + eocd_offset) {
 	zip_error_set(error, ZIP_ER_INCONS, 0);
 	return NULL;
     }
```
