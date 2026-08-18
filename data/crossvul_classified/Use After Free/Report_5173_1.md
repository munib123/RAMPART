# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5173_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5173_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 995-1035 of the vulnerable file.

		} else if (php_zip_property_reader(obj, hnd, &tmp, 0 TSRMLS_CC) == SUCCESS) {
			Z_SET_REFCOUNT_P(tmp, 1);
			Z_UNSET_ISREF_P(tmp);
			if (type == 1) {
				retval = zend_is_true(tmp);
			} else if (type == 0) {
				retval = (Z_TYPE_P(tmp) != IS_NULL);
			}
		}

		zval_ptr_dtor(&tmp);
	} else {
		std_hnd = zend_get_std_object_handlers();
		retval = std_hnd->has_property(object, member, type, key TSRMLS_CC);
	}

	if (member == &tmp_member) {
		zval_dtor(member);
	}
	return retval;
}
/* }}} */

static HashTable *php_zip_get_properties(zval *object TSRMLS_DC)/* {{{ */
{
	ze_zip_object *obj;
	zip_prop_handler *hnd;
	HashTable *props;
	zval *val;
	int ret;
	char *key;
	uint key_len;
	HashPosition pos;
	ulong num_key;

	obj = (ze_zip_object *)zend_objects_get_address(object TSRMLS_CC);
	props = zend_std_get_properties(object TSRMLS_CC);

	if (obj->prop_handler == NULL) {
		return NULL;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1012,6 +1012,14 @@
 		zval_dtor(member);
 	}
 	return retval;
+}
+/* }}} */
+
+static HashTable *php_zip_get_gc(zval *object, zval ***gc_data, int *gc_data_count TSRMLS_DC) /* {{{ */
+{
+	*gc_data = NULL;
+	*gc_data_count = 0;
+	return zend_std_get_properties(object TSRMLS_CC);
 }
 /* }}} */
 
@@ -2777,6 +2785,7 @@
 	zip_object_handlers.clone_obj		= NULL;
 	zip_object_handlers.get_property_ptr_ptr = php_zip_get_property_ptr_ptr;
 
+	zip_object_handlers.get_gc          = php_zip_get_gc;
 	zip_object_handlers.get_properties = php_zip_get_properties;
 	zip_object_handlers.read_property	= php_zip_read_property;
 	zip_object_handlers.has_property	= php_zip_has_property;
```
