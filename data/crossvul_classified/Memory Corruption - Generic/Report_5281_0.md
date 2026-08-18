# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5281_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5281_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1568-1608 of the vulnerable file.

		}
	}

	DBG_RETURN(PASS);
}
/* }}} */

/* {{{ php_mysqlnd_rowp_read_text_protocol */
enum_func_status
php_mysqlnd_rowp_read_text_protocol_aux(MYSQLND_MEMORY_POOL_CHUNK * row_buffer, zval ** fields,
									unsigned int field_count, const MYSQLND_FIELD * fields_metadata,
									zend_bool as_int_or_float, zend_bool copy_data, MYSQLND_STATS * stats TSRMLS_DC)
{
	
	unsigned int i;
	zend_bool last_field_was_string = FALSE;
	zval **current_field, **end_field, **start_field;
	zend_uchar * p = row_buffer->ptr;
	size_t data_size = row_buffer->app;
	zend_uchar * bit_area = (zend_uchar*) row_buffer->ptr + data_size + 1; /* we allocate from here */

	DBG_ENTER("php_mysqlnd_rowp_read_text_protocol_aux");

	if (!fields) {
		DBG_RETURN(FAIL);
	}

	end_field = (start_field = fields) + field_count;

	for (i = 0, current_field = start_field; current_field < end_field; current_field++, i++) {
		DBG_INF("Directly creating zval");
		MAKE_STD_ZVAL(*current_field);
		if (!*current_field) {
			DBG_RETURN(FAIL);
		}
	}

	for (i = 0, current_field = start_field; current_field < end_field; current_field++, i++) {
		/* Don't reverse the order. It is significant!*/
		zend_uchar *this_field_len_pos = p;
		/* php_mysqlnd_net_field_length() call should be after *this_field_len_pos = p; */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1585,6 +1585,7 @@
 	zend_uchar * p = row_buffer->ptr;
 	size_t data_size = row_buffer->app;
 	zend_uchar * bit_area = (zend_uchar*) row_buffer->ptr + data_size + 1; /* we allocate from here */
+	const zend_uchar * const packet_end = (zend_uchar*) row_buffer->ptr + data_size;
 
 	DBG_ENTER("php_mysqlnd_rowp_read_text_protocol_aux");
 
@@ -1606,8 +1607,13 @@
 		/* Don't reverse the order. It is significant!*/
 		zend_uchar *this_field_len_pos = p;
 		/* php_mysqlnd_net_field_length() call should be after *this_field_len_pos = p; */
-		unsigned long len = php_mysqlnd_net_field_length(&p);
-
+		const unsigned long len = php_mysqlnd_net_field_length(&p);
+
+		if (len != MYSQLND_NULL_LENGTH && ((p + len) > packet_end)) {
+			php_error_docref(NULL, E_WARNING, "Malformed server packet. Field length pointing "MYSQLND_SZ_T_SPEC
+											  " bytes after end of packet", (p + len) - packet_end - 1);
+			DBG_RETURN(FAIL);
+		}
 		if (copy_data == FALSE && current_field > start_field && last_field_was_string) {
 			/*
 			  Normal queries:
```
