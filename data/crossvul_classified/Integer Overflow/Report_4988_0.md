# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4988_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4988_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1264-1304 of the vulnerable file.

{
	zval * zip_entry;
	zend_long len = 0;
	zip_read_rsrc * zr_rsrc;
	zend_string *buffer;
	int n = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|l", &zip_entry, &len) == FAILURE) {
		return;
	}

	if ((zr_rsrc = (zip_read_rsrc *)zend_fetch_resource(Z_RES_P(zip_entry), le_zip_entry_name, le_zip_entry)) == NULL) {
		RETURN_FALSE;
	}

	if (len <= 0) {
		len = 1024;
	}

	if (zr_rsrc->zf) {
		buffer = zend_string_alloc(len, 0);
		n = zip_fread(zr_rsrc->zf, ZSTR_VAL(buffer), ZSTR_LEN(buffer));
		if (n > 0) {
			ZSTR_VAL(buffer)[n] = '\0';
			ZSTR_LEN(buffer) = n;
			RETURN_NEW_STR(buffer);
		} else {
			zend_string_free(buffer);
			RETURN_EMPTY_STRING()
		}
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

static void php_zip_entry_get_info(INTERNAL_FUNCTION_PARAMETERS, int opt) /* {{{ */
{
	zval * zip_entry;
	zip_read_rsrc * zr_rsrc;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1281,7 +1281,7 @@
 	}
 
 	if (zr_rsrc->zf) {
-		buffer = zend_string_alloc(len, 0);
+		buffer = zend_string_safe_alloc(1, len, 0, 0);
 		n = zip_fread(zr_rsrc->zf, ZSTR_VAL(buffer), ZSTR_LEN(buffer));
 		if (n > 0) {
 			ZSTR_VAL(buffer)[n] = '\0';
@@ -2728,7 +2728,7 @@
 		RETURN_FALSE;
 	}
 
-	buffer = zend_string_alloc(len, 0);
+	buffer = zend_string_safe_alloc(1, len, 0, 0);
 	n = zip_fread(zf, ZSTR_VAL(buffer), ZSTR_LEN(buffer));
 	if (n < 1) {
 		zend_string_free(buffer);
```
