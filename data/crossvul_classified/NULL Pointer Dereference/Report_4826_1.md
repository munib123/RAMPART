# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4826_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4826_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 891-931 of the vulnerable file.


	if (!strcmp((char *)name, EL_STRING) || !strcmp((char *)name, EL_NUMBER) ||
		!strcmp((char *)name, EL_BOOLEAN) || !strcmp((char *)name, EL_NULL) ||
	  	!strcmp((char *)name, EL_ARRAY) || !strcmp((char *)name, EL_STRUCT) ||
		!strcmp((char *)name, EL_RECORDSET) || !strcmp((char *)name, EL_BINARY) ||
		!strcmp((char *)name, EL_DATETIME)) {
		wddx_stack_top(stack, (void**)&ent1);

		if (Z_TYPE(ent1->data) == IS_UNDEF) {
			if (stack->top > 1) {
				stack->top--;
				efree(ent1);
			} else {
				stack->done = 1;
			}
			return;
		}

		if (!strcmp((char *)name, EL_BINARY)) {
			zend_string *new_str = NULL;
			
			if (ZSTR_EMPTY_ALLOC() != Z_STR(ent1->data)) {
				new_str = php_base64_decode(
					(unsigned char *)Z_STRVAL(ent1->data), Z_STRLEN(ent1->data));
			}

			zval_ptr_dtor(&ent1->data);
			if (new_str) {
				ZVAL_STR(&ent1->data, new_str);
			} else {
				ZVAL_EMPTY_STRING(&ent1->data);
			}
		}

		/* Call __wakeup() method on the object. */
		if (Z_TYPE(ent1->data) == IS_OBJECT) {
			zval fname, retval;

			ZVAL_STRING(&fname, "__wakeup");

			call_user_function_ex(NULL, &ent1->data, &fname, &retval, 0, 0, 0, NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -908,7 +908,7 @@
 
 		if (!strcmp((char *)name, EL_BINARY)) {
 			zend_string *new_str = NULL;
-			
+
 			if (ZSTR_EMPTY_ALLOC() != Z_STR(ent1->data)) {
 				new_str = php_base64_decode(
 					(unsigned char *)Z_STRVAL(ent1->data), Z_STRLEN(ent1->data));
@@ -967,22 +967,26 @@
 							php_error_docref(NULL, E_WARNING, "Class %s can not be unserialized", Z_STRVAL(ent1->data));
 						} else {
 							/* Initialize target object */
-							object_init_ex(&obj, pce);
-
-							/* Merge current hashtable with object's default properties */
-							zend_hash_merge(Z_OBJPROP(obj),
-											Z_ARRVAL(ent2->data),
-											zval_add_ref, 0);
-
-							if (incomplete_class) {
-								php_store_class_name(&obj, Z_STRVAL(ent1->data), Z_STRLEN(ent1->data));
+							if (object_init_ex(&obj, pce) != SUCCESS || EG(exception)) {
+								zval_ptr_dtor(&ent2->data);
+								ZVAL_UNDEF(&ent2->data);
+								php_error_docref(NULL, E_WARNING, "Class %s can not be instantiated", Z_STRVAL(ent1->data));
+							} else {
+								/* Merge current hashtable with object's default properties */
+								zend_hash_merge(Z_OBJPROP(obj),
+												Z_ARRVAL(ent2->data),
+												zval_add_ref, 0);
+
+								if (incomplete_class) {
+									php_store_class_name(&obj, Z_STRVAL(ent1->data), Z_STRLEN(ent1->data));
+								}
+
+								/* Clean up old array entry */
+								zval_ptr_dtor(&ent2->data);
+
+								/* Set stack entry to point to the newly created object */
+								ZVAL_COPY_VALUE(&ent2->data, &obj);
 							}
-
-							/* Clean up old array entry */
-							zval_ptr_dtor(&ent2->data);
-
-							/* Set stack entry to point to the newly created object */
-							ZVAL_COPY_VALUE(&ent2->data, &obj);
 						}
 
 						/* Clean up class name var entry */
```
