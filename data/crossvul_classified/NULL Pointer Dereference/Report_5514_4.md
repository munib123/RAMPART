# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5514_4
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5514_4`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 454-494 of the vulnerable file.


/* {{{ php_wddx_serialize_unset
 */
static void php_wddx_serialize_unset(wddx_packet *packet)
{
	php_wddx_add_chunk_static(packet, WDDX_NULL);
}
/* }}} */

/* {{{ php_wddx_serialize_object
 */
static void php_wddx_serialize_object(wddx_packet *packet, zval *obj)
{
/* OBJECTS_FIXME */
	zval **ent, *fname, **varname;
	zval *retval = NULL;
	const char *key;
	ulong idx;
	char tmp_buf[WDDX_BUF_LEN];
	HashTable *objhash, *sleephash;
	TSRMLS_FETCH();

	MAKE_STD_ZVAL(fname);
	ZVAL_STRING(fname, "__sleep", 1);

	/*
	 * We try to call __sleep() method on object. It's supposed to return an
	 * array of property names to be serialized.
	 */
	if (call_user_function_ex(CG(function_table), &obj, fname, &retval, 0, 0, 1, NULL TSRMLS_CC) == SUCCESS) {
		if (retval && (sleephash = HASH_OF(retval))) {
			PHP_CLASS_ATTRIBUTES;

			PHP_SET_CLASS_ATTRIBUTES(obj);

			php_wddx_add_chunk_static(packet, WDDX_STRUCT_S);
			snprintf(tmp_buf, WDDX_BUF_LEN, WDDX_VAR_S, PHP_CLASS_NAME_VAR);
			php_wddx_add_chunk(packet, tmp_buf);
			php_wddx_add_chunk_static(packet, WDDX_STRING_S);
			php_wddx_add_chunk_ex(packet, class_name, name_len);
			php_wddx_add_chunk_static(packet, WDDX_STRING_E);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -471,21 +471,26 @@
 	ulong idx;
 	char tmp_buf[WDDX_BUF_LEN];
 	HashTable *objhash, *sleephash;
+	zend_class_entry *ce;
+	PHP_CLASS_ATTRIBUTES;
 	TSRMLS_FETCH();
+
+	PHP_SET_CLASS_ATTRIBUTES(obj);
+	ce = Z_OBJCE_P(obj);
+	if (!ce || ce->serialize || ce->unserialize) {
+		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Class %s can not be serialized", class_name);
+		PHP_CLEANUP_CLASS_ATTRIBUTES();
+		return;
+	}
 
 	MAKE_STD_ZVAL(fname);
 	ZVAL_STRING(fname, "__sleep", 1);
-
 	/*
 	 * We try to call __sleep() method on object. It's supposed to return an
 	 * array of property names to be serialized.
 	 */
 	if (call_user_function_ex(CG(function_table), &obj, fname, &retval, 0, 0, 1, NULL TSRMLS_CC) == SUCCESS) {
 		if (retval && (sleephash = HASH_OF(retval))) {
-			PHP_CLASS_ATTRIBUTES;
-
-			PHP_SET_CLASS_ATTRIBUTES(obj);
-
 			php_wddx_add_chunk_static(packet, WDDX_STRUCT_S);
 			snprintf(tmp_buf, WDDX_BUF_LEN, WDDX_VAR_S, PHP_CLASS_NAME_VAR);
 			php_wddx_add_chunk(packet, tmp_buf);
@@ -494,8 +499,6 @@
 			php_wddx_add_chunk_static(packet, WDDX_STRING_E);
 			php_wddx_add_chunk_static(packet, WDDX_VAR_E);
 
-			PHP_CLEANUP_CLASS_ATTRIBUTES();
-
 			objhash = HASH_OF(obj);
 
 			for (zend_hash_internal_pointer_reset(sleephash);
@@ -516,10 +519,6 @@
 	} else {
 		uint key_len;
 
-		PHP_CLASS_ATTRIBUTES;
-
-		PHP_SET_CLASS_ATTRIBUTES(obj);
-
 		php_wddx_add_chunk_static(packet, WDDX_STRUCT_S);
 		snprintf(tmp_buf, WDDX_BUF_LEN, WDDX_VAR_S, PHP_CLASS_NAME_VAR);
 		php_wddx_add_chunk(packet, tmp_buf);
@@ -528,8 +527,6 @@
 		php_wddx_add_chunk_static(packet, WDDX_STRING_E);
 		php_wddx_add_chunk_static(packet, WDDX_VAR_E);
 
-		PHP_CLEANUP_CLASS_ATTRIBUTES();
-
 		objhash = HASH_OF(obj);
 		for (zend_hash_internal_pointer_reset(objhash);
 			 zend_hash_get_current_data(objhash, (void**)&ent) == SUCCESS;
@@ -550,6 +547,8 @@
 		}
 		php_wddx_add_chunk_static(packet, WDDX_STRUCT_E);
 	}
+
+	PHP_CLEANUP_CLASS_ATTRIBUTES();
 
 	zval_dtor(fname);
 	FREE_ZVAL(fname);
@@ -1012,26 +1011,30 @@
 							pce = &PHP_IC_ENTRY;
 						}
 
-						/* Initialize target object */
-						MAKE_STD_ZVAL(obj);
-						object_init_ex(obj, *pce);
-
-						/* Merge current hashtable with object's default properties */
-						zend_hash_merge(Z_OBJPROP_P(obj),
-										Z_ARRVAL_P(ent2->data),
-										(void (*)(void *)) zval_add_ref,
-										(void *) &tmp, sizeof(zval *), 0);
-
-						if (incomplete_class) {
-							php_store_class_name(obj, Z_STRVAL_P(ent1->data), Z_STRLEN_P(ent1->data));
+						if (pce != &PHP_IC_ENTRY && ((*pce)->serialize || (*pce)->unserialize)) {
+							ent2->data = NULL;
+							php_error_docref(NULL TSRMLS_CC, E_WARNING, "Class %s can not be unserialized", Z_STRVAL_P(ent1->data));
+						} else {
+							/* Initialize target object */
+							MAKE_STD_ZVAL(obj);
+							object_init_ex(obj, *pce);
+
+							/* Merge current hashtable with object's default properties */
+							zend_hash_merge(Z_OBJPROP_P(obj),
+											Z_ARRVAL_P(ent2->data),
+											(void (*)(void *)) zval_add_ref,
+											(void *) &tmp, sizeof(zval *), 0);
+
+							if (incomplete_class) {
+								php_store_class_name(obj, Z_STRVAL_P(ent1->data), Z_STRLEN_P(ent1->data));
+							}
+
+							/* Clean up old array entry */
+							zval_ptr_dtor(&ent2->data);
+
+							/* Set stack entry to point to the newly created object */
+							ent2->data = obj;
 						}
-
-						/* Clean up old array entry */
-						zval_ptr_dtor(&ent2->data);
-
-						/* Set stack entry to point to the newly created object */
-						ent2->data = obj;
-
 						/* Clean up class name var entry */
 						zval_ptr_dtor(&ent1->data);
 					} else if (Z_TYPE_P(ent2->data) == IS_OBJECT) {
```
