# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2067_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2067_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 54-95 of the vulnerable file.

		$t_projects = array( $f_project_id );
	}

	$t_projects[] = ALL_PROJECTS; # add "ALL_PROJECTS to the list of projects to fetch

	$t_reqd_access = config_get( 'view_proj_doc_threshold' );
	if ( is_array( $t_reqd_access ) ) {
		if ( 1 == count( $t_reqd_access ) ) {
			$t_access_clause = "= " . array_shift( $t_reqd_access ) . " ";
		} else {
			$t_access_clause = "IN (" . implode( ',', $t_reqd_access ) . ")";
		}
	} else {
		$t_access_clause = ">= $t_reqd_access ";
	}

	$query = "SELECT pft.id, pft.project_id, pft.filename, pft.filesize, pft.title, pft.description, pft.date_added
				FROM $t_project_file_table pft
					LEFT JOIN $t_project_table pt ON pft.project_id = pt.id
					LEFT JOIN $t_project_user_list_table pult
						ON pft.project_id = pult.project_id AND pult.user_id = $t_user_id
					LEFT JOIN $t_user_table ut ON ut.id = $t_user_id
				WHERE pft.project_id in (" . implode( ',', $t_projects ) . ") AND
					( ( ( pt.view_state = $t_pub OR pt.view_state is null ) AND pult.user_id is null AND ut.access_level $t_access_clause ) OR
						( ( pult.user_id = $t_user_id ) AND ( pult.access_level $t_access_clause ) ) OR
						( ut.access_level >= $t_admin ) )
				ORDER BY pt.name ASC, pft.title ASC";
	$result = db_query( $query );
	$num_files = db_num_rows( $result );

	html_page_top( lang_get( 'docs_link' ) );
?>
<br />
<div align="center">
<table class="width100" cellspacing="1">
<tr>
	<td class="form-title">
		<?php echo lang_get( 'project_documentation_title' ) ?>
	</td>
	<td class="right">
		<?php print_doc_menu( 'proj_doc_page.php' ) ?>
	</td>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,14 +71,14 @@
 				FROM $t_project_file_table pft
 					LEFT JOIN $t_project_table pt ON pft.project_id = pt.id
 					LEFT JOIN $t_project_user_list_table pult
-						ON pft.project_id = pult.project_id AND pult.user_id = $t_user_id
-					LEFT JOIN $t_user_table ut ON ut.id = $t_user_id
+						ON pft.project_id = pult.project_id AND pult.user_id = " . db_param() . "
+					LEFT JOIN $t_user_table ut ON ut.id = " . db_param() . "
 				WHERE pft.project_id in (" . implode( ',', $t_projects ) . ") AND
-					( ( ( pt.view_state = $t_pub OR pt.view_state is null ) AND pult.user_id is null AND ut.access_level $t_access_clause ) OR
-						( ( pult.user_id = $t_user_id ) AND ( pult.access_level $t_access_clause ) ) OR
-						( ut.access_level >= $t_admin ) )
+					( ( ( pt.view_state = " . db_param() . " OR pt.view_state is null ) AND pult.user_id is null AND ut.access_level $t_access_clause ) OR
+						( ( pult.user_id = " . db_param() . " ) AND ( pult.access_level $t_access_clause ) ) OR
+						( ut.access_level >= " . db_param() . " ) )
 				ORDER BY pt.name ASC, pft.title ASC";
-	$result = db_query( $query );
+	$result = db_query_bound( $query, array( $t_user_id, $t_user_id, $t_pub, $t_user_id, $t_admin ) );
 	$num_files = db_num_rows( $result );
 
 	html_page_top( lang_get( 'docs_link' ) );
```
