# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2067_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2067_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 566-606 of the vulnerable file.

	foreach( $p_metrics['open'] as $t_enum => $t_value ) {
		$total[$t_enum] = $t_value + $p_metrics['resolved'][$t_enum] + $p_metrics['closed'][$t_enum];
	}
	return $total;
}

# --------------------
# Data Extractions
# --------------------
# --------------------
# summarize metrics by a single field in the bug table
function create_bug_enum_summary( $p_enum_string, $p_enum ) {
	$t_project_id = helper_get_current_project();
	$t_bug_table = db_get_table( 'mantis_bug_table' );
	$t_user_id = auth_get_current_user_id();
	$specific_where = " AND " . helper_project_specific_where( $t_project_id, $t_user_id );

	$t_metrics = array();
	$t_assoc_array = MantisEnum::getAssocArrayIndexedByValues( $p_enum_string );

	foreach ( $t_assoc_array as $t_value => $t_label  ) {
		$query = "SELECT COUNT(*)
					FROM $t_bug_table
					WHERE $p_enum='$t_value' $specific_where";
		$result = db_query( $query );
		$t_metrics[$t_label] = db_result( $result, 0 );
	}

	return $t_metrics;
}

# Function which gives the absolute values according to the status (opened/closed/resolved)
function enum_bug_group( $p_enum_string, $p_enum ) {
	$t_bug_table = db_get_table( 'mantis_bug_table' );

	$t_project_id = helper_get_current_project();
	$t_bug_table = db_get_table( 'mantis_bug_table' );
	$t_user_id = auth_get_current_user_id();
	$t_res_val = config_get( 'bug_resolved_status_threshold' );
	$t_clo_val = config_get( 'bug_closed_status_threshold' );
	$specific_where = " AND " . helper_project_specific_where( $t_project_id, $t_user_id );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -583,11 +583,15 @@
 	$t_metrics = array();
 	$t_assoc_array = MantisEnum::getAssocArrayIndexedByValues( $p_enum_string );
 
+	if( !db_field_exists( $p_enum, $t_bug_table ) ) {
+		trigger_error( ERROR_DB_FIELD_NOT_FOUND, ERROR );
+	}
+
 	foreach ( $t_assoc_array as $t_value => $t_label  ) {
 		$query = "SELECT COUNT(*)
 					FROM $t_bug_table
-					WHERE $p_enum='$t_value' $specific_where";
-		$result = db_query( $query );
+					WHERE $p_enum=" . db_param() . " $specific_where";
+		$result = db_query_bound( $query, array( $t_value ) );
 		$t_metrics[$t_label] = db_result( $result, 0 );
 	}
 
@@ -605,32 +609,36 @@
 	$t_clo_val = config_get( 'bug_closed_status_threshold' );
 	$specific_where = " AND " . helper_project_specific_where( $t_project_id, $t_user_id );
 
+	if( !db_field_exists( $p_enum, $t_bug_table ) ) {
+		trigger_error( ERROR_DB_FIELD_NOT_FOUND, ERROR );
+	}
+
 	$t_array_indexed_by_enum_values = MantisEnum::getAssocArrayIndexedByValues( $p_enum_string );
 	$enum_count = count( $t_array_indexed_by_enum_values );
 	foreach ( $t_array_indexed_by_enum_values as $t_value => $t_label ) {
 		# Calculates the number of bugs opened and puts the results in a table
 		$query = "SELECT COUNT(*)
 					FROM $t_bug_table
-					WHERE $p_enum='$t_value' AND
-						status<'$t_res_val' $specific_where";
-		$result2 = db_query( $query );
+					WHERE $p_enum=" . db_param() . " AND
+						status<" . db_param() . " $specific_where";
+		$result2 = db_query( $query, array( $t_value, $t_res_val ) );
 		$t_metrics['open'][$t_label] = db_result( $result2, 0, 0 );
 
 		# Calculates the number of bugs closed and puts the results in a table
 		$query = "SELECT COUNT(*)
 					FROM $t_bug_table
-					WHERE $p_enum='$t_value' AND
-						status>='$t_clo_val' $specific_where";
-		$result2 = db_query( $query );
+					WHERE $p_enum=" . db_param() . " AND
+						status>=" . db_param() . " $specific_where";
+		$result2 = db_query_bound( $query, array( $t_value, $t_clo_val ) );
 		$t_metrics['closed'][$t_label] = db_result( $result2, 0, 0 );
 
 		# Calculates the number of bugs resolved and puts the results in a table
 		$query = "SELECT COUNT(*)
 					FROM $t_bug_table
-					WHERE $p_enum='$t_value' AND
-						status>='$t_res_val'  AND
-						status<'$t_clo_val' $specific_where";
-		$result2 = db_query( $query );
+					WHERE $p_enum=" . db_param() . " AND
+						status>=" . db_param() . " AND
+						status<" . db_param() . " $specific_where";
+		$result2 = db_query_bound( $query, array(  $t_value, $t_res_val, $t_clo_val ) );
 		$t_metrics['resolved'][$t_label] = db_result( $result2, 0, 0 );
 	}
 
@@ -818,12 +826,12 @@
 			FROM $t_bug_table LEFT JOIN $t_history_table
 			ON $t_bug_table.id = $t_history_table.bug_id
 			WHERE $specific_where
-						AND $t_bug_table.status >= '$t_res_val'
-						AND ( ( $t_history_table.new_value >= '$t_res_val'
+						AND $t_bug_table.status >= " . db_param() . "
+						AND ( ( $t_history_table.new_value >= " . db_param() . "
 								AND $t_history_table.field_name = 'status' )
 						OR $t_history_table.id is NULL )
 			ORDER BY $t_bug_table.id, date_modified ASC";
-	$result = db_query( $query );
+	$result = db_query( $query, array( $t_res_val, $t_res_val ) );
 	$bug_count = db_num_rows( $result );
 
 	$t_last_id = 0;
```
