# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2347_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2347_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 589-629 of the vulnerable file.

		foreach( $t_custom_fields as $t_cfid ) {
			if( is_array( gpc_get( 'custom_field_' . $t_cfid, null ) ) ) {
				$f_custom_fields_data[$t_cfid] = gpc_get_string_array( 'custom_field_' . $t_cfid, META_FILTER_ANY );
			} else {
				$f_custom_fields_data[$t_cfid] = gpc_get_string( 'custom_field_' . $t_cfid, META_FILTER_ANY );
				$f_custom_fields_data[$t_cfid] = array(
					$f_custom_fields_data[$t_cfid],
				);
			}
		}
	}

	# validate sorting
	$t_fields = helper_get_columns_to_view();
	$t_n_fields = count( $t_fields );
	for( $i = 0;$i < $t_n_fields;$i++ ) {
		if( isset( $t_fields[$i] ) && in_array( $t_fields[$i], array( 'selection', 'edit', 'bugnotes_count', 'attachment_count' ) ) ) {
			unset( $t_fields[$i] );
		}
	}
	$t_sort_fields = explode( ',', $p_filter_arr['sort'] );
	$t_dir_fields = explode( ',', $p_filter_arr['dir'] );
	for( $i = 0;$i < 2;$i++ ) {
		if( isset( $t_sort_fields[$i] ) ) {
			$t_drop = false;
			$t_sort = $t_sort_fields[$i];
			if( strpos( $t_sort, 'custom_' ) === 0 ) {
				if( false === custom_field_get_id_from_name( utf8_substr( $t_sort, utf8_strlen( 'custom_' ) ) ) ) {
					$t_drop = true;
				}
			} else {
				if( !in_array( $t_sort, $t_fields ) ) {
					$t_drop = true;
				}
			}
			if( !in_array( $t_dir_fields[$i], array( "ASC", "DESC" ) ) ) {
				$t_drop = true;
			}
			if( $t_drop ) {
				unset( $t_sort_fields[$i] );
				unset( $t_dir_fields[$i] );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -606,8 +606,20 @@
 			unset( $t_fields[$i] );
 		}
 	}
+
+	# Make sure array is no longer than 2 elements
 	$t_sort_fields = explode( ',', $p_filter_arr['sort'] );
+	if( count( $t_sort_fields ) > 2 ) {
+		$t_sort_fields = array_slice( $t_sort_fields, 0, 2 );
+	}
+
+	# Make sure array is no longer than 2 elements
 	$t_dir_fields = explode( ',', $p_filter_arr['dir'] );
+	if( count( $t_dir_fields ) > 2 ) {
+		$t_dir_fields = array_slice( $t_dir_fields, 0, 2 );
+	}
+
+	# Validate the max of two segments for $t_sort_fields and $t_dir_fields
 	for( $i = 0;$i < 2;$i++ ) {
 		if( isset( $t_sort_fields[$i] ) ) {
 			$t_drop = false;
```
