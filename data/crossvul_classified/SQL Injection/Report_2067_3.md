# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2067_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2067_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 60-100 of the vulnerable file.

# this function prints out the summary for the given enum setting
# The enum field name is passed in through $p_enum
function summary_print_by_enum( $p_enum ) {
	$t_project_id = helper_get_current_project();
	$t_user_id = auth_get_current_user_id();

	$t_project_filter = helper_project_specific_where( $t_project_id );
	if( ' 1<>1' == $t_project_filter ) {
		return;
	}

	$t_filter_prefix = config_get( 'bug_count_hyperlink_prefix' );

	$t_mantis_bug_table = db_get_table( 'mantis_bug_table' );
	$t_status_query = ( 'status' == $p_enum ) ? '' : ' ,status ';
	$query = "SELECT COUNT(id) as bugcount, $p_enum $t_status_query
				FROM $t_mantis_bug_table
				WHERE $t_project_filter
				GROUP BY $p_enum $t_status_query
				ORDER BY $p_enum $t_status_query";
	$result = db_query( $query );

	$t_last_value = -1;
	$t_bugs_open = 0;
	$t_bugs_resolved = 0;
	$t_bugs_closed = 0;
	$t_bugs_total = 0;

	$t_resolved_val = config_get( 'bug_resolved_status_threshold' );
	$t_closed_val = config_get( 'bug_closed_status_threshold' );

	while( $row = db_fetch_array( $result ) ) {
		if(( $row[$p_enum] != $t_last_value ) && ( -1 != $t_last_value ) ) {

			# Build up the hyperlinks to bug views
			$t_bug_link = '';
			switch( $p_enum ) {
				case 'status':
					$t_bug_link = '<a class="subtle" href="' . $t_filter_prefix . '&amp;' . FILTER_PROPERTY_STATUS_ID . '=' . $t_last_value;
					break;
				case 'severity':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,7 +77,7 @@
 				WHERE $t_project_filter
 				GROUP BY $p_enum $t_status_query
 				ORDER BY $p_enum $t_status_query";
-	$result = db_query( $query );
+	$result = db_query_bound( $query );
 
 	$t_last_value = -1;
 	$t_bugs_open = 0;
@@ -374,10 +374,10 @@
 		return;
 	}
 	$query = "SELECT * FROM $t_mantis_bug_table
-				WHERE status < $t_resolved
+				WHERE status < " . db_param() . "
 				AND $specific_where
 				ORDER BY date_submitted ASC, priority DESC";
-	$result = db_query( $query );
+	$result = db_query_bound( $query, array( $t_resolved ) );
 
 	$t_count = 0;
 	$t_private_bug_threshold = config_get( 'private_bug_threshold' );
@@ -423,7 +423,7 @@
 				WHERE handler_id>0 AND $specific_where
 				GROUP BY handler_id, status
 				ORDER BY handler_id, status";
-	$result = db_query( $query );
+	$result = db_query_bound( $query );
 
 	$t_last_handler = -1;
 	$t_bugs_open = 0;
@@ -524,7 +524,7 @@
 				WHERE $specific_where
 				GROUP BY reporter_id
 				ORDER BY num DESC";
-	$result = db_query( $query, $t_reporter_summary_limit );
+	$result = db_query_bound( $query, null, $t_reporter_summary_limit );
 
 	$t_reporters = array();
 	while( $row = db_fetch_array( $result ) ) {
@@ -536,11 +536,11 @@
 	foreach( $t_reporters as $t_reporter ) {
 		$v_reporter_id = $t_reporter;
 		$query = "SELECT COUNT(id) as bugcount, status FROM $t_mantis_bug_table
-					WHERE reporter_id=$v_reporter_id
+					WHERE reporter_id=" . db_param() . "
 					AND $specific_where
 					GROUP BY status
 					ORDER BY status";
-		$result2 = db_query( $query );
+		$result2 = db_query_bound( $query, array( $v_reporter_id ) );
 
 		$last_reporter = -1;
 		$t_bugs_open = 0;
@@ -608,7 +608,7 @@
 				GROUP BY $t_project_query c.name, b.category_id, b.status
 				ORDER BY $t_project_query c.name";
 
-	$result = db_query( $query );
+	$result = db_query_bound( $query );
 
 	$last_category_name = -1;
 	$last_category_id = -1;
```
