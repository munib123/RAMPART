# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5285_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5285_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 291-331 of the vulnerable file.


	old_object = zend_objects_get_address(zobject TSRMLS_CC);
	new_obj_val = spl_array_object_new_ex(old_object->ce, &intern, zobject, 1 TSRMLS_CC);
	new_object = &intern->std;

	zend_objects_clone_members(new_object, new_obj_val, old_object, handle TSRMLS_CC);

	return new_obj_val;
}
/* }}} */

static zval **spl_array_get_dimension_ptr_ptr(int check_inherited, zval *object, zval *offset, int type TSRMLS_DC) /* {{{ */
{
	spl_array_object *intern = (spl_array_object*)zend_object_store_get_object(object TSRMLS_CC);
	zval **retval;
	char *key;
	uint len;
	long index;
	HashTable *ht = spl_array_get_hash_table(intern, 0 TSRMLS_CC);

	if (!offset) {
		return &EG(uninitialized_zval_ptr);
	}

	if ((type == BP_VAR_W || type == BP_VAR_RW) && (ht->nApplyCount > 0)) {
		zend_error(E_WARNING, "Modification of ArrayObject during sorting is prohibited");
		return &EG(error_zval_ptr);;
	}

	switch (Z_TYPE_P(offset)) {
	case IS_STRING:
		key = Z_STRVAL_P(offset);
		len = Z_STRLEN_P(offset) + 1;
string_offest:
		if (zend_symtable_find(ht, key, len, (void **) &retval) == FAILURE) {
			switch (type) {
				case BP_VAR_R:
					zend_error(E_NOTICE, "Undefined index: %s", key);
				case BP_VAR_UNSET:
				case BP_VAR_IS:
					retval = &EG(uninitialized_zval_ptr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -308,7 +308,7 @@
 	long index;
 	HashTable *ht = spl_array_get_hash_table(intern, 0 TSRMLS_CC);
 
-	if (!offset) {
+	if (!offset || !ht) {
 		return &EG(uninitialized_zval_ptr);
 	}
 
@@ -626,7 +626,7 @@
 		HashTable *ht = spl_array_get_hash_table(intern, 0 TSRMLS_CC);
 
 		switch(Z_TYPE_P(offset)) {
-			case IS_STRING: 
+			case IS_STRING:
 				if (zend_symtable_find(ht, Z_STRVAL_P(offset), Z_STRLEN_P(offset)+1, (void **) &tmp) != FAILURE) {
 					if (check_empty == 2) {
 						return 1;
@@ -638,7 +638,7 @@
 
 			case IS_DOUBLE:
 			case IS_RESOURCE:
-			case IS_BOOL: 
+			case IS_BOOL:
 			case IS_LONG:
 				if (offset->type == IS_DOUBLE) {
 					index = (long)Z_DVAL_P(offset);
@@ -1810,7 +1810,9 @@
 		intern->ar_flags |= flags & SPL_ARRAY_CLONE_MASK;
 		zval_ptr_dtor(&intern->array);
 		ALLOC_INIT_ZVAL(intern->array);
-		if (!php_var_unserialize(&intern->array, &p, s + buf_len, &var_hash TSRMLS_CC)) {
+		if (!php_var_unserialize(&intern->array, &p, s + buf_len, &var_hash TSRMLS_CC)
+				|| (Z_TYPE_P(intern->array) != IS_ARRAY && Z_TYPE_P(intern->array) != IS_OBJECT)) {
+			zval_ptr_dtor(&intern->array);
 			goto outexcept;
 		}
 		var_push_dtor(&var_hash, &intern->array);
```
