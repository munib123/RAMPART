# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2067_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2067_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 249-289 of the vulnerable file.


	$t_projects = current_user_get_all_accessible_subprojects( $p_project_id );
	$t_projects[] = (int)$p_project_id;
	if( ALL_PROJECTS != $p_project_id ) {
		$t_projects[] = ALL_PROJECTS;
	}

	$t_news_table = db_get_table( 'mantis_news_table' );
	$t_news_view_limit = config_get( 'news_view_limit' );
	$t_news_view_limit_days = config_get( 'news_view_limit_days' ) * SECONDS_PER_DAY;

	switch( config_get( 'news_limit_method' ) ) {
		case 0:

			# BY_LIMIT - Select the news posts
			$query = "SELECT *
						FROM $t_news_table";

			if( 1 == count( $t_projects ) ) {
				$c_project_id = $t_projects[0];
				$query .= " WHERE project_id='$c_project_id'";
			} else {
				$query .= ' WHERE project_id IN (' . join( $t_projects, ',' ) . ')';
			}

			$query .= ' ORDER BY announcement DESC, id DESC';
			$result = db_query( $query, $t_news_view_limit, $c_offset );
			break;
		case 1:

			# BY_DATE - Select the news posts
			$query = "SELECT *
						FROM $t_news_table WHERE
						( " . db_helper_compare_days( 0, 'date_posted', "< $t_news_view_limit_days" ) . "
						 OR announcement = " . db_param() . " ) ";
			$t_params = Array(
				db_now(),
				1,
			);
			if( 1 == count( $t_projects ) ) {
				$c_project_id = $t_projects[0];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -266,13 +266,15 @@
 
 			if( 1 == count( $t_projects ) ) {
 				$c_project_id = $t_projects[0];
-				$query .= " WHERE project_id='$c_project_id'";
+				$query .= " WHERE project_id=" . db_params();
+				$t_params = array( $c_project_id );
 			} else {
 				$query .= ' WHERE project_id IN (' . join( $t_projects, ',' ) . ')';
+				$t_params = null;
 			}
 
 			$query .= ' ORDER BY announcement DESC, id DESC';
-			$result = db_query( $query, $t_news_view_limit, $c_offset );
+			$result = db_query_bound( $query, $t_params, $t_news_view_limit, $c_offset );
 			break;
 		case 1:
 
```
