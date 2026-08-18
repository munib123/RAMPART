# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5514_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5514_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 2321-2361 of the vulnerable file.


	INIT_CLASS_ENTRY(ce, "PDOStatement", pdo_dbstmt_functions);
	pdo_dbstmt_ce = zend_register_internal_class(&ce TSRMLS_CC);
	pdo_dbstmt_ce->get_iterator = pdo_stmt_iter_get;
	pdo_dbstmt_ce->create_object = pdo_dbstmt_new;
	zend_class_implements(pdo_dbstmt_ce TSRMLS_CC, 1, zend_ce_traversable);
	zend_declare_property_null(pdo_dbstmt_ce, "queryString", sizeof("queryString")-1, ZEND_ACC_PUBLIC TSRMLS_CC);

	memcpy(&pdo_dbstmt_object_handlers, &std_object_handlers, sizeof(zend_object_handlers));
	pdo_dbstmt_object_handlers.write_property = dbstmt_prop_write;
	pdo_dbstmt_object_handlers.unset_property = dbstmt_prop_delete;
	pdo_dbstmt_object_handlers.get_method = dbstmt_method_get;
	pdo_dbstmt_object_handlers.compare_objects = dbstmt_compare;
	pdo_dbstmt_object_handlers.clone_obj = dbstmt_clone_obj;

	INIT_CLASS_ENTRY(ce, "PDORow", pdo_row_functions);
	pdo_row_ce = zend_register_internal_class(&ce TSRMLS_CC);
	pdo_row_ce->ce_flags |= ZEND_ACC_FINAL_CLASS; /* when removing this a lot of handlers need to be redone */
	pdo_row_ce->create_object = pdo_row_new;
	pdo_row_ce->serialize = pdo_row_serialize;
}

static void free_statement(pdo_stmt_t *stmt TSRMLS_DC)
{
	if (stmt->bound_params) {
		zend_hash_destroy(stmt->bound_params);
		FREE_HASHTABLE(stmt->bound_params);
		stmt->bound_params = NULL;
	}
	if (stmt->bound_param_map) {
		zend_hash_destroy(stmt->bound_param_map);
		FREE_HASHTABLE(stmt->bound_param_map);
		stmt->bound_param_map = NULL;
	}
	if (stmt->bound_columns) {
		zend_hash_destroy(stmt->bound_columns);
		FREE_HASHTABLE(stmt->bound_columns);
		stmt->bound_columns = NULL;
	}

	if (stmt->methods && stmt->methods->dtor) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2338,6 +2338,7 @@
 	pdo_row_ce->ce_flags |= ZEND_ACC_FINAL_CLASS; /* when removing this a lot of handlers need to be redone */
 	pdo_row_ce->create_object = pdo_row_new;
 	pdo_row_ce->serialize = pdo_row_serialize;
+	pdo_row_ce->unserialize = zend_class_unserialize_deny;
 }
 
 static void free_statement(pdo_stmt_t *stmt TSRMLS_DC)
```
