# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 5255_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5255_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 907-947 of the vulnerable file.

	if (newlen) {
		*newlen = buf.len;
	}
	smart_str_0(&buf);
	*newstr = buf.c;
	PHP_VAR_SERIALIZE_DESTROY(var_hash);

	return SUCCESS;
}
/* }}} */

PS_SERIALIZER_DECODE_FUNC(php_binary) /* {{{ */
{
	const char *p;
	char *name;
	const char *endptr = val + vallen;
	zval *current;
	int namelen;
	int has_value;
	php_unserialize_data_t var_hash;

	PHP_VAR_UNSERIALIZE_INIT(var_hash);

	for (p = val; p < endptr; ) {
		zval **tmp;
		namelen = ((unsigned char)(*p)) & (~PS_BIN_UNDEF);

		if (namelen < 0 || namelen > PS_BIN_MAX || (p + namelen) >= endptr) {
			PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
			return FAILURE;
		}

		has_value = *p & PS_BIN_UNDEF ? 0 : 1;

		name = estrndup(p + 1, namelen);

		p += namelen + 1;

		if (zend_hash_find(&EG(symbol_table), name, namelen + 1, (void **) &tmp) == SUCCESS) {
			if ((Z_TYPE_PP(tmp) == IS_ARRAY && Z_ARRVAL_PP(tmp) == &EG(symbol_table)) || *tmp == PS(http_session_vars)) {
				efree(name);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -924,11 +924,13 @@
 	int namelen;
 	int has_value;
 	php_unserialize_data_t var_hash;
+	int skip = 0;
 
 	PHP_VAR_UNSERIALIZE_INIT(var_hash);
 
 	for (p = val; p < endptr; ) {
 		zval **tmp;
+		skip = 0;
 		namelen = ((unsigned char)(*p)) & (~PS_BIN_UNDEF);
 
 		if (namelen < 0 || namelen > PS_BIN_MAX || (p + namelen) >= endptr) {
@@ -944,22 +946,25 @@
 
 		if (zend_hash_find(&EG(symbol_table), name, namelen + 1, (void **) &tmp) == SUCCESS) {
 			if ((Z_TYPE_PP(tmp) == IS_ARRAY && Z_ARRVAL_PP(tmp) == &EG(symbol_table)) || *tmp == PS(http_session_vars)) {
-				efree(name);
-				continue;
+				skip = 1;
 			}
 		}
 
 		if (has_value) {
 			ALLOC_INIT_ZVAL(current);
 			if (php_var_unserialize(&current, (const unsigned char **) &p, (const unsigned char *) endptr, &var_hash TSRMLS_CC)) {
-				php_set_session_var(name, namelen, current, &var_hash  TSRMLS_CC);
+				if (!skip) {
+					php_set_session_var(name, namelen, current, &var_hash  TSRMLS_CC);
+				}
 			} else {
 				PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
 				return FAILURE;
 			}
 			var_push_dtor_no_addref(&var_hash, &current);
 		}
-		PS_ADD_VARL(name, namelen);
+		if (!skip) {
+			PS_ADD_VARL(name, namelen);
+		}
 		efree(name);
 	}
 
@@ -1016,6 +1021,7 @@
 	int namelen;
 	int has_value;
 	php_unserialize_data_t var_hash;
+	int skip = 0;
 
 	PHP_VAR_UNSERIALIZE_INIT(var_hash);
 
@@ -1024,6 +1030,7 @@
 	while (p < endptr) {
 		zval **tmp;
 		q = p;
+		skip = 0;
 		while (*q != PS_DELIMITER) {
 			if (++q >= endptr) goto break_outer_loop;
 		}
@@ -1040,14 +1047,16 @@
 
 		if (zend_hash_find(&EG(symbol_table), name, namelen + 1, (void **) &tmp) == SUCCESS) {
 			if ((Z_TYPE_PP(tmp) == IS_ARRAY && Z_ARRVAL_PP(tmp) == &EG(symbol_table)) || *tmp == PS(http_session_vars)) {
-				goto skip;
+				skip = 1;
 			}
 		}
 
 		if (has_value) {
 			ALLOC_INIT_ZVAL(current);
 			if (php_var_unserialize(&current, (const unsigned char **) &q, (const unsigned char *) endptr, &var_hash TSRMLS_CC)) {
-				php_set_session_var(name, namelen, current, &var_hash  TSRMLS_CC);
+				if (!skip) {
+					php_set_session_var(name, namelen, current, &var_hash  TSRMLS_CC);
+				}
 			} else {
 				var_push_dtor_no_addref(&var_hash, &current);
 				efree(name);
@@ -1056,7 +1065,9 @@
 			}
 			var_push_dtor_no_addref(&var_hash, &current);
 		}
-		PS_ADD_VARL(name, namelen);
+		if (!skip) {
+			PS_ADD_VARL(name, namelen);
+		}
 skip:
 		efree(name);
 
```
