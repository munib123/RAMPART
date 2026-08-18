# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5516_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5516_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1019-1059 of the vulnerable file.

		RETURN_FALSE;
	}

	if (buf.s) {
		RETURN_NEW_STR(buf.s);
	} else {
		RETURN_NULL();
	}
}
/* }}} */

/* {{{ proto mixed unserialize(string variable_representation[, array allowed_classes])
   Takes a string representation of variable and recreates it */
PHP_FUNCTION(unserialize)
{
	char *buf = NULL;
	size_t buf_len;
	const unsigned char *p;
	php_unserialize_data_t var_hash;
	zval *options = NULL, *classes = NULL;
	HashTable *class_hash = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|a", &buf, &buf_len, &options) == FAILURE) {
		RETURN_FALSE;
	}

	if (buf_len == 0) {
		RETURN_FALSE;
	}

	p = (const unsigned char*) buf;
	PHP_VAR_UNSERIALIZE_INIT(var_hash);
	if(options != NULL) {
		classes = zend_hash_str_find(Z_ARRVAL_P(options), "allowed_classes", sizeof("allowed_classes")-1);
		if(classes && (Z_TYPE_P(classes) == IS_ARRAY || !zend_is_true(classes))) {
			ALLOC_HASHTABLE(class_hash);
			zend_hash_init(class_hash, (Z_TYPE_P(classes) == IS_ARRAY)?zend_hash_num_elements(Z_ARRVAL_P(classes)):0, NULL, NULL, 0);
		}
		if(class_hash && Z_TYPE_P(classes) == IS_ARRAY) {
			zval *entry;
			zend_string *lcname;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1036,6 +1036,7 @@
 	const unsigned char *p;
 	php_unserialize_data_t var_hash;
 	zval *options = NULL, *classes = NULL;
+	zval *retval;
 	HashTable *class_hash = NULL;
 
 	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|a", &buf, &buf_len, &options) == FAILURE) {
@@ -1067,22 +1068,21 @@
 		}
 	}
 
-	if (!php_var_unserialize_ex(return_value, &p, p + buf_len, &var_hash, class_hash)) {
+	retval = var_tmp_var(&var_hash);
+	if (!php_var_unserialize_ex(retval, &p, p + buf_len, &var_hash, class_hash)) {
 		PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
 		if (class_hash) {
 			zend_hash_destroy(class_hash);
 			FREE_HASHTABLE(class_hash);
 		}
-		zval_ptr_dtor(return_value);
 		if (!EG(exception)) {
 			php_error_docref(NULL, E_NOTICE, "Error at offset " ZEND_LONG_FMT " of %zd bytes",
 				(zend_long)((char*)p - buf), buf_len);
 		}
 		RETURN_FALSE;
 	}
-	/* We should keep an reference to return_value to prevent it from being dtor
-	   in case nesting calls to unserialize */
-	var_push_dtor(&var_hash, return_value);
+
+	ZVAL_COPY(return_value, retval);
 
 	PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
 	if (class_hash) {
```
