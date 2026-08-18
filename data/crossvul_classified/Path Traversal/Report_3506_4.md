# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3506_4
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3506_4`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 34-76 of the vulnerable file.

	$f_page_number		= gpc_get_int( 'page_number', 1 );

	$t_per_page = null;
	$t_bug_count = null;
	$t_page_count = null;

	$rows = filter_get_bug_rows( $f_page_number, $t_per_page, $t_page_count, $t_bug_count, null, null, null, true );
	if ( $rows === false ) {
		print_header_redirect( 'view_all_set.php?type=0' );
	}

	$t_bugslist = Array();
	$t_users_handlers = Array();
	$t_project_ids  = Array();
	$t_row_count = count( $rows );
	for($i=0; $i < $t_row_count; $i++) {
		array_push($t_bugslist, $rows[$i]->id );
		$t_users_handlers[] = $rows[$i]->handler_id;
		$t_project_ids[] = $rows[$i]->project_id;
	}
	user_cache_array_rows( array_unique( $t_users_handlers ) );
	project_cache_array_rows( array_unique( $t_project_ids ) );
	
	gpc_set_cookie( config_get( 'bug_list_cookie' ), implode( ',', $t_bugslist ) );

	compress_enable();

	# don't index view issues pages
	html_robots_noindex();

	html_page_top1( lang_get( 'view_bugs_link' ) );

	if ( current_user_get_pref( 'refresh_delay' ) > 0 ) {
		html_meta_redirect( 'view_all_bug_page.php?page_number='.$f_page_number, current_user_get_pref( 'refresh_delay' )*60 );
	}

	html_page_top2();

	print_recently_visited();

	include( dirname( __FILE__ ) . DIRECTORY_SEPARATOR . 'view_all_inc.php' );

	html_page_bottom();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,9 +51,11 @@
 		$t_users_handlers[] = $rows[$i]->handler_id;
 		$t_project_ids[] = $rows[$i]->project_id;
 	}
-	user_cache_array_rows( array_unique( $t_users_handlers ) );
-	project_cache_array_rows( array_unique( $t_project_ids ) );
-	
+	$t_unique_users_handlers = array_unique( $t_users_handlers );
+	$t_unique_project_ids = array_unique( $t_project_ids );
+	user_cache_array_rows( $t_unique_users_handlers );
+	project_cache_array_rows( $t_unique_project_ids );
+
 	gpc_set_cookie( config_get( 'bug_list_cookie' ), implode( ',', $t_bugslist ) );
 
 	compress_enable();
```
