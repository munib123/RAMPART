# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5171_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5171_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 811-851 of the vulnerable file.

		if (intern->debug_info == NULL) {
			ALLOC_HASHTABLE(intern->debug_info);
			ZEND_INIT_SYMTABLE_EX(intern->debug_info, zend_hash_num_elements(intern->std.properties) + 1, 0);
		}

		if (intern->debug_info->nApplyCount == 0) {
			zend_hash_clean(intern->debug_info);
			zend_hash_copy(intern->debug_info, intern->std.properties, (copy_ctor_func_t) zval_add_ref, (void *) &tmp, sizeof(zval *));

			storage = intern->array;
			zval_add_ref(&storage);

			base = (Z_OBJ_HT_P(obj) == &spl_handler_ArrayIterator) ? spl_ce_ArrayIterator : spl_ce_ArrayObject;
			zname = spl_gen_private_prop_name(base, "storage", sizeof("storage")-1, &name_len TSRMLS_CC);
			zend_symtable_update(intern->debug_info, zname, name_len+1, &storage, sizeof(zval *), NULL);
			efree(zname);
		}

		return intern->debug_info;
	}
}
/* }}} */

static zval *spl_array_read_property(zval *object, zval *member, int type, const zend_literal *key TSRMLS_DC) /* {{{ */
{
	spl_array_object *intern = (spl_array_object*)zend_object_store_get_object(object TSRMLS_CC);

	if ((intern->ar_flags & SPL_ARRAY_ARRAY_AS_PROPS) != 0
	&& !std_object_handlers.has_property(object, member, 2, key TSRMLS_CC)) {
		return spl_array_read_dimension(object, member, type TSRMLS_CC);
	}
	return std_object_handlers.read_property(object, member, type, key TSRMLS_CC);
} /* }}} */

static void spl_array_write_property(zval *object, zval *member, zval *value, const zend_literal *key TSRMLS_DC) /* {{{ */
{
	spl_array_object *intern = (spl_array_object*)zend_object_store_get_object(object TSRMLS_CC);

	if ((intern->ar_flags & SPL_ARRAY_ARRAY_AS_PROPS) != 0
	&& !std_object_handlers.has_property(object, member, 2, key TSRMLS_CC)) {
		spl_array_write_dimension(object, member, value TSRMLS_CC);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -831,6 +831,16 @@
 }
 /* }}} */
 
+static HashTable *spl_array_get_gc(zval *object, zval ***gc_data, int *gc_data_count TSRMLS_DC) /* {{{ */
+{
+	spl_array_object *intern = (spl_array_object*)zend_object_store_get_object(object TSRMLS_CC);
+
+	*gc_data = &intern->array;
+	*gc_data_count = 1;
+	return zend_std_get_properties(object);
+}
+/* }}} */
+
 static zval *spl_array_read_property(zval *object, zval *member, int type, const zend_literal *key TSRMLS_DC) /* {{{ */
 {
 	spl_array_object *intern = (spl_array_object*)zend_object_store_get_object(object TSRMLS_CC);
@@ -1961,6 +1971,7 @@
 
 	spl_handler_ArrayObject.get_properties = spl_array_get_properties;
 	spl_handler_ArrayObject.get_debug_info = spl_array_get_debug_info;
+	spl_handler_ArrayObject.get_gc = spl_array_get_gc;
 	spl_handler_ArrayObject.read_property = spl_array_read_property;
 	spl_handler_ArrayObject.write_property = spl_array_write_property;
 	spl_handler_ArrayObject.get_property_ptr_ptr = spl_array_get_property_ptr_ptr;
```
