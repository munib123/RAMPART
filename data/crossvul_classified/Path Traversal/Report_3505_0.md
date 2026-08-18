# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3505_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3505_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 18-58 of the vulnerable file.

	 * @package MantisBT
	 * @copyright Copyright (C) 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
	 * @copyright Copyright (C) 2002 - 2011  MantisBT Team - mantisbt-dev@lists.sourceforge.net
	 * @link http://www.mantisbt.org
	 */
	 /**
	  * MantisBT Core API's
	  */
	require_once( 'core.php' );

	require_once( 'bug_api.php' );
	require_once( 'bug_group_action_api.php' );

	auth_ensure_user_authenticated();

	helper_begin_long_process();

	$f_action = gpc_get_string( 'action' );
	$f_bug_arr	= gpc_get_int_array( 'bug_arr', array() );

	$t_action_include_file = 'bug_actiongroup_' . $f_action . '_inc.php';
	$t_form_name = 'bug_actiongroup_' . $f_action;

	form_security_validate( $t_form_name );

	require_once( dirname( __FILE__ ) . DIRECTORY_SEPARATOR . $t_action_include_file );

	# group bugs by project
	$t_projects_bugs = array();
	foreach( $f_bug_arr as $t_bug_id ) {
		bug_ensure_exists( $t_bug_id );
		$t_bug = bug_get( $t_bug_id, true );

		if ( isset( $t_projects_bugs[$t_bug->project_id] ) ) {
		  $t_projects_bugs[$t_bug->project_id][] = $t_bug_id;
        } else {
		  $t_projects_bugs[$t_bug->project_id] = array( $t_bug_id );
        }
    }

	$t_failed_ids = array();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,12 +35,11 @@
 	$f_action = gpc_get_string( 'action' );
 	$f_bug_arr	= gpc_get_int_array( 'bug_arr', array() );
 
-	$t_action_include_file = 'bug_actiongroup_' . $f_action . '_inc.php';
 	$t_form_name = 'bug_actiongroup_' . $f_action;
 
 	form_security_validate( $t_form_name );
 
-	require_once( dirname( __FILE__ ) . DIRECTORY_SEPARATOR . $t_action_include_file );
+	bug_group_action_init( $f_action );
 
 	# group bugs by project
 	$t_projects_bugs = array();
```
