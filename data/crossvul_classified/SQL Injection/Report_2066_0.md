# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2066_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2066_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 137-177 of the vulnerable file.


		# add history entry
		history_log_event_special( $t_issue_id, FILE_ADDED, $p_name );
	}

	return $t_attachment_id;
}

/**
 * Returns the attachment contents
 *
 * @param int $p_file_id
 * @param string $p_type The file type, bug or doc
 * @param int $p_user_id
 * @return string|soap_fault the string contents, or a soap_fault
 */
function mci_file_get( $p_file_id, $p_type, $p_user_id ) {

	# we handle the case where the file is attached to a bug
	# or attached to a project as a project doc.
	$query = '';
	switch( $p_type ) {
		case 'bug':
			$t_bug_file_table = db_get_table( 'mantis_bug_file_table' );
			$query = "SELECT *
				FROM $t_bug_file_table
				WHERE id='$p_file_id'";
			break;
		case 'doc':
			$t_project_file_table = db_get_table( 'mantis_project_file_table' );
			$query = "SELECT *
				FROM $t_project_file_table
				WHERE id='$p_file_id'";
			break;
		default:
			return SoapObjectsFactory::newSoapFault( 'Server', 'Invalid file type '.$p_type. ' .' );
	}

	$result = db_query( $query );

	if ( $result->EOF ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -154,25 +154,21 @@
 
 	# we handle the case where the file is attached to a bug
 	# or attached to a project as a project doc.
-	$query = '';
+	$t_query = '';
 	switch( $p_type ) {
 		case 'bug':
 			$t_bug_file_table = db_get_table( 'mantis_bug_file_table' );
-			$query = "SELECT *
-				FROM $t_bug_file_table
-				WHERE id='$p_file_id'";
+			$t_query = "SELECT * FROM $t_bug_file_table WHERE id=" . db_param();
 			break;
 		case 'doc':
 			$t_project_file_table = db_get_table( 'mantis_project_file_table' );
-			$query = "SELECT *
-				FROM $t_project_file_table
-				WHERE id='$p_file_id'";
+			$t_query = "SELECT * FROM $t_project_file_table WHERE id=" . db_param();
 			break;
 		default:
 			return SoapObjectsFactory::newSoapFault( 'Server', 'Invalid file type '.$p_type. ' .' );
 	}
 
-	$result = db_query( $query );
+	$result = db_query_bound( $t_query, array( $p_file_id ) );
 
 	if ( $result->EOF ) {
 		return SoapObjectsFactory::newSoapFault( 'Client', 'Unable to find an attachment with type ' . $p_type. ' and id ' . $p_file_id . ' .' );
```
