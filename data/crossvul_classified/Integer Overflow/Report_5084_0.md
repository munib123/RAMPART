# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5084_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5084_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1741-1781 of the vulnerable file.


/* {{{ proto string fread(resource fp, int length)
   Binary-safe file read */
PHPAPI PHP_FUNCTION(fread)
{
	zval *arg1;
	long len;
	php_stream *stream;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &arg1, &len) == FAILURE) {
		RETURN_FALSE;
	}

	PHP_STREAM_TO_ZVAL(stream, &arg1);

	if (len <= 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Length parameter must be greater than 0");
		RETURN_FALSE;
	}

	Z_STRVAL_P(return_value) = emalloc(len + 1);
	Z_STRLEN_P(return_value) = php_stream_read(stream, Z_STRVAL_P(return_value), len);

	/* needed because recv/read/gzread doesnt put a null at the end*/
	Z_STRVAL_P(return_value)[Z_STRLEN_P(return_value)] = 0;
	Z_TYPE_P(return_value) = IS_STRING;
}
/* }}} */

static const char *php_fgetcsv_lookup_trailing_spaces(const char *ptr, size_t len, const char delimiter TSRMLS_DC) /* {{{ */
{
	int inc_len;
	unsigned char last_chars[2] = { 0, 0 };

	while (len > 0) {
		inc_len = (*ptr == '\0' ? 1: php_mblen(ptr, len));
		switch (inc_len) {
			case -2:
			case -1:
				inc_len = 1;
				php_ignore_value(php_mblen(NULL, 0));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1755,6 +1755,12 @@
 
 	if (len <= 0) {
 		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Length parameter must be greater than 0");
+		RETURN_FALSE;
+	}
+
+	if (len > INT_MAX) {
+		/* string length is int in 5.x so we can not read more than int */
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Length parameter must be no more than %d", INT_MAX);
 		RETURN_FALSE;
 	}
 
```
