# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3596_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3596_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 133-173 of the vulnerable file.

			$t_failed_ids[$t_bug_id] = lang_get( 'bug_actiongroup_access' );
		}
		break;

	case 'MOVE':
		$f_project_id = gpc_get_int( 'project_id' );
		if( access_has_bug_level( config_get( 'move_bug_threshold' ), $t_bug_id ) &&
		    access_has_project_level( config_get( 'report_bug_threshold', null, null, $f_project_id ), $f_project_id ) ) {
			/** @todo we need to issue a helper_call_custom_function( 'issue_update_validate', array( $t_bug_id, $t_bug_data, $f_bugnote_text ) ); */
			bug_move( $t_bug_id, $f_project_id );
			helper_call_custom_function( 'issue_update_notify', array( $t_bug_id ) );
		} else {
			$t_failed_ids[$t_bug_id] = lang_get( 'bug_actiongroup_access' );
		}
		break;

	case 'COPY':
		$f_project_id = gpc_get_int( 'project_id' );

		if ( access_has_project_level( config_get( 'report_bug_threshold' ), $f_project_id ) ) {
			bug_copy( $t_bug_id, $f_project_id, true, true, true, true, true, true );
		} else {
			$t_failed_ids[$t_bug_id] = lang_get( 'bug_actiongroup_access' );
		}
		break;

	case 'ASSIGN':
		$f_assign = gpc_get_int( 'assign' );
		if ( ON == config_get( 'auto_set_status_to_assigned' ) ) {
			$t_assign_status = config_get( 'bug_assigned_status' );
		} else {
			$t_assign_status = $t_status;
		}
		# check that new handler has rights to handle the issue, and
		#  that current user has rights to assign the issue
		$t_threshold = access_get_status_threshold( $t_assign_status, bug_get_field( $t_bug_id, 'project_id' ) );
		if ( access_has_bug_level( config_get( 'update_bug_assign_threshold', config_get( 'update_bug_threshold' ) ), $t_bug_id ) ) {
			if ( access_has_bug_level( config_get( 'handle_bug_threshold' ), $t_bug_id, $f_assign ) ) {
				if ( bug_check_workflow( $t_status, $t_assign_status ) ) {
					/** @todo we need to issue a helper_call_custom_function( 'issue_update_validate', array( $t_bug_id, $t_bug_data, $f_bugnote_text ) ); */
					bug_assign( $t_bug_id, $f_assign, $f_bug_notetext, $f_bug_noteprivate );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,7 +150,8 @@
 		$f_project_id = gpc_get_int( 'project_id' );
 
 		if ( access_has_project_level( config_get( 'report_bug_threshold' ), $f_project_id ) ) {
-			bug_copy( $t_bug_id, $f_project_id, true, true, true, true, true, true );
+			# Copy everything except history
+			bug_copy( $t_bug_id, $f_project_id, true, true, false, true, true, true );
 		} else {
 			$t_failed_ids[$t_bug_id] = lang_get( 'bug_actiongroup_access' );
 		}
```
