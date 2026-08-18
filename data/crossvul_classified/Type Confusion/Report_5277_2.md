# CrossVul Fix Pair: Incorrect Type Conversion or Cast in c
**Pair ID:** 5277_2
**Vulnerability Class:** Type Confusion
**CWE:** CWE-704
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5277_2`)

## Vulnerability Information & PoC

## Description
Incorrect Type Conversion or Cast - The product does not correctly convert an object, resource, or structure from one type to a different type.

## Vulnerable Code
```c
Lines 453-493 of the vulnerable file.

			zend_hash_index_find(params, hkey.num, (void *) &ptr);
		}

		zdata_ptr = &zdata;

		if (Z_TYPE_PP(ptr) == IS_ARRAY
		&&	SUCCESS == zend_hash_find(Z_ARRVAL_PP(ptr), "value", sizeof("value"), (void *) &ptr)
		&&	SUCCESS == zend_hash_get_current_data(Z_ARRVAL_PP(zdata_ptr), (void *) &zdata_ptr)
		) {
			/*
			 * params = [arr => [value => [0 => 1]]]
			 *                            ^- ptr
			 * zdata  = [arr => [0 => NULL]]
			 *                  ^- zdata_ptr
			 */
			zval **test_ptr;

			while (Z_TYPE_PP(zdata_ptr) == IS_ARRAY
			&&	SUCCESS == zend_hash_get_current_data(Z_ARRVAL_PP(zdata_ptr), (void *) &test_ptr)
			) {
				if (Z_TYPE_PP(test_ptr) == IS_ARRAY) {

					/* now find key in ptr */
					if (HASH_KEY_IS_STRING == zend_hash_get_current_key_ex(Z_ARRVAL_PP(zdata_ptr), &hkey.str, &hkey.len, &hkey.num, hkey.dup, NULL)) {
						if (SUCCESS == zend_hash_find(Z_ARRVAL_PP(ptr), hkey.str, hkey.len, (void *) &ptr)) {
							zdata_ptr = test_ptr;
						} else {
							Z_ADDREF_PP(test_ptr);
							zend_hash_update(Z_ARRVAL_PP(ptr), hkey.str, hkey.len, (void *) test_ptr, sizeof(zval *), (void *) &ptr);
							break;
						}
					} else {
						if (SUCCESS == zend_hash_index_find(Z_ARRVAL_PP(ptr), hkey.num, (void *) &ptr)) {
							zdata_ptr = test_ptr;
						} else if (hkey.num) {
							Z_ADDREF_PP(test_ptr);
							zend_hash_index_update(Z_ARRVAL_PP(ptr), hkey.num, (void *) test_ptr, sizeof(zval *), (void *) &ptr);
							break;
						} else {
							Z_ADDREF_PP(test_ptr);
							zend_hash_next_index_insert(Z_ARRVAL_PP(ptr), (void *) test_ptr, sizeof(zval *), (void *) &ptr);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -470,7 +470,7 @@
 			while (Z_TYPE_PP(zdata_ptr) == IS_ARRAY
 			&&	SUCCESS == zend_hash_get_current_data(Z_ARRVAL_PP(zdata_ptr), (void *) &test_ptr)
 			) {
-				if (Z_TYPE_PP(test_ptr) == IS_ARRAY) {
+				if (Z_TYPE_PP(test_ptr) == IS_ARRAY && Z_TYPE_PP(ptr) == IS_ARRAY) {
 
 					/* now find key in ptr */
 					if (HASH_KEY_IS_STRING == zend_hash_get_current_key_ex(Z_ARRVAL_PP(zdata_ptr), &hkey.str, &hkey.len, &hkey.num, hkey.dup, NULL)) {
```
