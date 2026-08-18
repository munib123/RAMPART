# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2067_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2067_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 689-730 of the vulnerable file.

	}

	$t_projects[] = ALL_PROJECTS; # add ALL_PROJECTS to the list of projects to fetch


	$t_reqd_access = config_get( 'view_proj_doc_threshold' );
	if( is_array( $t_reqd_access ) ) {
		if( 1 == count( $t_reqd_access ) ) {
			$t_access_clause = "= " . array_shift( $t_reqd_access ) . " ";
		} else {
			$t_access_clause = "IN (" . implode( ',', $t_reqd_access ) . ")";
		}
	} else {
		$t_access_clause = ">= $t_reqd_access ";
	}

	$query = "SELECT pft.id, pft.project_id, pft.filename, pft.file_type, pft.filesize, pft.title, pft.description, pft.date_added, pft.user_id
		FROM $t_project_file_table pft
		LEFT JOIN $t_project_table pt ON pft.project_id = pt.id
		LEFT JOIN $t_project_user_list_table pult
		ON pft.project_id = pult.project_id AND pult.user_id = $t_user_id
		LEFT JOIN $t_user_table ut ON ut.id = $t_user_id
		WHERE pft.project_id in (" . implode( ',', $t_projects ) . ") AND
		( ( ( pt.view_state = $t_pub OR pt.view_state is null ) AND pult.user_id is null AND ut.access_level $t_access_clause ) OR
		( ( pult.user_id = $t_user_id ) AND ( pult.access_level $t_access_clause ) ) OR
		( ut.access_level = $t_admin ) )
		ORDER BY pt.name ASC, pft.title ASC";
	$result = db_query( $query );
	$num_files = db_num_rows( $result );

	$t_result = array();
	for( $i = 0;$i < $num_files;$i++ ) {
		$row = db_fetch_array( $result );

		$t_attachment = array();
		$t_attachment['id'] = $row['id'];
		$t_attachment['filename'] = $row['filename'];
		$t_attachment['title'] = $row['title'];
		$t_attachment['description'] = $row['description'];
		$t_attachment['size'] = $row['filesize'];
		$t_attachment['content_type'] = $row['file_type'];
		$t_attachment['date_submitted'] = SoapObjectsFactory::newDateTimeVar( $row['date_added'] );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -706,14 +706,14 @@
 		FROM $t_project_file_table pft
 		LEFT JOIN $t_project_table pt ON pft.project_id = pt.id
 		LEFT JOIN $t_project_user_list_table pult
-		ON pft.project_id = pult.project_id AND pult.user_id = $t_user_id
-		LEFT JOIN $t_user_table ut ON ut.id = $t_user_id
+		ON pft.project_id = pult.project_id AND pult.user_id = " . db_param() . "
+		LEFT JOIN $t_user_table ut ON ut.id = " . db_param() . "
 		WHERE pft.project_id in (" . implode( ',', $t_projects ) . ") AND
-		( ( ( pt.view_state = $t_pub OR pt.view_state is null ) AND pult.user_id is null AND ut.access_level $t_access_clause ) OR
-		( ( pult.user_id = $t_user_id ) AND ( pult.access_level $t_access_clause ) ) OR
-		( ut.access_level = $t_admin ) )
+		( ( ( pt.view_state = " . db_param() . " OR pt.view_state is null ) AND pult.user_id is null AND ut.access_level $t_access_clause ) OR
+		( ( pult.user_id = " . db_param() . " ) AND ( pult.access_level $t_access_clause ) ) OR
+		( ut.access_level = " . db_param() . " ) )
 		ORDER BY pt.name ASC, pft.title ASC";
-	$result = db_query( $query );
+	$result = db_query_bound( $query, array( $t_user_id, $t_user_id, $t_pub, $t_user_id, $t_admin ) );
 	$num_files = db_num_rows( $result );
 
 	$t_result = array();
```
