# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3505_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3505_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 25-65 of the vulnerable file.

	 /**
	  * MantisBT Core API's
	  */
	require_once( 'core.php' );

	require_once( 'bug_group_action_api.php' );

	auth_ensure_user_authenticated();

	$f_action = gpc_get_string( 'action', '' );
	$f_bug_arr = gpc_get_int_array( 'bug_arr', array() );

	# redirects to all_bug_page if nothing is selected
	if ( is_blank( $f_action ) || ( 0 == count( $f_bug_arr ) ) ) {
		print_header_redirect( 'view_all_bug_page.php' );
	}

	# run through the issues to see if they are all from one project
	$t_project_id = ALL_PROJECTS;
	$t_multiple_projects = false;

	bug_cache_array_rows( $f_bug_arr );

	foreach( $f_bug_arr as $t_bug_id ) {
		$t_bug = bug_get( $t_bug_id );
		if ( $t_project_id != $t_bug->project_id ) {
			if ( ( $t_project_id != ALL_PROJECTS ) && !$t_multiple_projects ) {
				$t_multiple_projects = true;
			} else {
				$t_project_id = $t_bug->project_id;
			}
		}
	}
	if ( $t_multiple_projects ) {
		$t_project_id = ALL_PROJECTS;
	}
	# override the project if necessary
	if( $t_project_id != helper_get_current_project() ) {
		# in case the current project is not the same project of the bug we are viewing...
		# ... override the current project. This to avoid problems with categories and handlers lists etc.
		$g_project_override = $t_project_id;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,7 @@
 	# run through the issues to see if they are all from one project
 	$t_project_id = ALL_PROJECTS;
 	$t_multiple_projects = false;
+	$t_projects = array();
 
 	bug_cache_array_rows( $f_bug_arr );
 
@@ -52,11 +53,13 @@
 				$t_multiple_projects = true;
 			} else {
 				$t_project_id = $t_bug->project_id;
+				$t_projects[$t_project_id] = $t_project_id;
 			}
 		}
 	}
 	if ( $t_multiple_projects ) {
 		$t_project_id = ALL_PROJECTS;
+		$t_projects[ALL_PROJECTS] = ALL_PROJECTS;
 	}
 	# override the project if necessary
 	if( $t_project_id != helper_get_current_project() ) {
```
