# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5658_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5658_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 524-565 of the vulnerable file.


	res = rad_get_attr(raddesc->radh, &data, &len);
	if (res == -1) {
		RETURN_FALSE;
	} else {
		if (res > 0) {

			array_init(return_value);
			add_assoc_long(return_value, "attr", res);
			add_assoc_stringl(return_value, "data", (char *) data, len, 1);
			return;
		}
		RETURN_LONG(res);
	}
}
/* }}} */

/* {{{ proto string radius_get_vendor_attr(data) */
PHP_FUNCTION(radius_get_vendor_attr)
{
	int res;
	const void *data;
	int len;
	u_int32_t vendor;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &len) == FAILURE) {
		return;
	}

	res = rad_get_vendor_attr(&vendor, &data, (size_t *) &len);
	if (res == -1) {
		RETURN_FALSE;
	} else {

		array_init(return_value);
		add_assoc_long(return_value, "attr", res);
		add_assoc_long(return_value, "vendor", vendor);
		add_assoc_stringl(return_value, "data", (char *) data, len, 1);
		return;
	}
}
/* }}} */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -541,24 +541,24 @@
 /* {{{ proto string radius_get_vendor_attr(data) */
 PHP_FUNCTION(radius_get_vendor_attr)
 {
-	int res;
-	const void *data;
+	const void *data, *raw;
 	int len;
 	u_int32_t vendor;
-
-	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &len) == FAILURE) {
-		return;
-	}
-
-	res = rad_get_vendor_attr(&vendor, &data, (size_t *) &len);
-	if (res == -1) {
+	unsigned char type;
+	size_t data_len;
+
+	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &raw, &len) == FAILURE) {
+		return;
+	}
+
+	if (rad_get_vendor_attr(&vendor, &type, &data, &data_len, raw, len) == -1) {
 		RETURN_FALSE;
 	} else {
 
 		array_init(return_value);
-		add_assoc_long(return_value, "attr", res);
+		add_assoc_long(return_value, "attr", type);
 		add_assoc_long(return_value, "vendor", vendor);
-		add_assoc_stringl(return_value, "data", (char *) data, len, 1);
+		add_assoc_stringl(return_value, "data", (char *) data, data_len, 1);
 		return;
 	}
 }
```
