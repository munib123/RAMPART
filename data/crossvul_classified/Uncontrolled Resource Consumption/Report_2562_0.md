# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 2562_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2562_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 220-260 of the vulnerable file.

			 * to have the same (plain text) cookie name for the same path and we should not overwrite
			 * more specific cookies with the less specific ones.
			 */
			if (PG(http_globals)[TRACK_VARS_COOKIE] &&
				symtable1 == Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_COOKIE]) &&
				zend_symtable_exists(symtable1, index, index_len + 1)) {
				zval_ptr_dtor(&gpc_element);
			} else {
				zend_symtable_update(symtable1, index, index_len + 1, &gpc_element, sizeof(zval *), (void **) &gpc_element_p);
			}
		}
	}
	free_alloca(var_orig, use_heap);
}

typedef struct post_var_data {
	smart_str str;
	char *ptr;
	char *end;
	uint64_t cnt;
} post_var_data_t;

static zend_bool add_post_var(zval *arr, post_var_data_t *var, zend_bool eof TSRMLS_DC)
{
	char *ksep, *vsep, *val;
	size_t klen, vlen;
	/* FIXME: string-size_t */
	unsigned int new_vlen;

	if (var->ptr >= var->end) {
		return 0;
	}

	vsep = memchr(var->ptr, '&', var->end - var->ptr);
	if (!vsep) {
		if (!eof) {
			return 0;
		} else {
			vsep = var->end;
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -237,11 +237,14 @@
 	char *ptr;
 	char *end;
 	uint64_t cnt;
+
+	/* Bytes in ptr that have already been scanned for '&' */
+	size_t already_scanned;
 } post_var_data_t;
 
 static zend_bool add_post_var(zval *arr, post_var_data_t *var, zend_bool eof TSRMLS_DC)
 {
-	char *ksep, *vsep, *val;
+	char *start, *ksep, *vsep, *val;
 	size_t klen, vlen;
 	/* FIXME: string-size_t */
 	unsigned int new_vlen;
@@ -250,9 +253,11 @@
 		return 0;
 	}
 
-	vsep = memchr(var->ptr, '&', var->end - var->ptr);
+	start = var->ptr + var->already_scanned;
+	vsep = memchr(start, '&', var->end - start);
 	if (!vsep) {
 		if (!eof) {
+			var->already_scanned = var->end - var->ptr;
 			return 0;
 		} else {
 			vsep = var->end;
@@ -285,6 +290,7 @@
 	efree(val);
 
 	var->ptr = vsep + (vsep != var->end);
+	var->already_scanned = 0;
 	return 1;
 }
 
@@ -304,7 +310,7 @@
 		}
 	}
 
-	if (!eof) {
+	if (!eof && vars->str.c != vars->ptr) {
 		memmove(vars->str.c, vars->ptr, vars->str.len = vars->end - vars->ptr);
 	}
 	return SUCCESS;
```
