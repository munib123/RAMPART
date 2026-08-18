# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5263_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5263_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3500-3540 of the vulnerable file.

	}

	if (ch->in_callback) {
		php_error_docref(NULL, E_WARNING, "Attempt to reset cURL handle from a callback");
		return;
	}

	curl_easy_reset(ch->cp);
	_php_curl_reset_handlers(ch);
	_php_curl_set_default_options(ch);
}
/* }}} */
#endif

#if LIBCURL_VERSION_NUM > 0x070f03 /* 7.15.4 */
/* {{{ proto void curl_escape(resource ch, string str)
   URL encodes the given string */
PHP_FUNCTION(curl_escape)
{
	char       *str = NULL, *res = NULL;
	size_t        str_len = 0;
	zval       *zid;
	php_curl   *ch;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "rs", &zid, &str, &str_len) == FAILURE) {
		return;
	}

	if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
		RETURN_FALSE;
	}

	if ((res = curl_easy_escape(ch->cp, str, str_len))) {
		RETVAL_STRING(res);
		curl_free(res);
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3517,7 +3517,7 @@
 PHP_FUNCTION(curl_escape)
 {
 	char       *str = NULL, *res = NULL;
-	size_t        str_len = 0;
+	size_t     str_len = 0;
 	zval       *zid;
 	php_curl   *ch;
 
@@ -3526,6 +3526,10 @@
 	}
 
 	if ((ch = (php_curl*)zend_fetch_resource(Z_RES_P(zid), le_curl_name, le_curl)) == NULL) {
+		RETURN_FALSE;
+	}
+
+	if (ZEND_SIZE_T_INT_OVFL(str_len)) {
 		RETURN_FALSE;
 	}
 
@@ -3556,7 +3560,7 @@
 		RETURN_FALSE;
 	}
 
-	if (str_len > INT_MAX) {
+	if (ZEND_SIZE_T_INT_OVFL(str_len)) {
 		RETURN_FALSE;
 	}
 
```
