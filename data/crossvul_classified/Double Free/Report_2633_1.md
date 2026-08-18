# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2633_1
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2633_1`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 562-604 of the vulnerable file.

    }

    if (!_zip_buffer_ok(buffer)) {
        zip_error_set(error, ZIP_ER_INTERNAL, 0);
        if (!from_buffer) {
            _zip_buffer_free(buffer);
        }
        return -1;
    }
    if (!from_buffer) {
        _zip_buffer_free(buffer);
    }

    /* zip_source_seek / zip_source_tell don't support values > ZIP_INT64_MAX */
    if (zde->offset > ZIP_INT64_MAX) {
	zip_error_set(error, ZIP_ER_SEEK, EFBIG);
	return -1;
    }

    if (!_zip_dirent_process_winzip_aes(zde, error)) {
	if (!from_buffer) {
	    _zip_buffer_free(buffer);
	}
	return -1;
    }

    zde->extra_fields = _zip_ef_remove_internal(zde->extra_fields);

    return (zip_int64_t)(size + variable_size);
}


static zip_string_t *
_zip_dirent_process_ef_utf_8(const zip_dirent_t *de, zip_uint16_t id, zip_string_t *str)
{
    zip_uint16_t ef_len;
    zip_uint32_t ef_crc;
    zip_buffer_t *buffer;

    const zip_uint8_t *ef = _zip_ef_get_by_id(de->extra_fields, &ef_len, id, 0, ZIP_EF_BOTH, NULL);

    if (ef == NULL || ef_len < 5 || ef[0] != 1) {
	return str;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -579,9 +579,6 @@
     }
 
     if (!_zip_dirent_process_winzip_aes(zde, error)) {
-	if (!from_buffer) {
-	    _zip_buffer_free(buffer);
-	}
 	return -1;
     }
 
```
