# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3600_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3600_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 119-160 of the vulnerable file.

			helper_call_custom_function( 'issue_update_notify', array( $t_bug_id ) );
		} else {
				$t_failed_ids[$t_bug_id] = lang_get( 'bug_actiongroup_status' );
			}
		} else {
			$t_failed_ids[$t_bug_id] = lang_get( 'bug_actiongroup_access' );
		}
		break;

	case 'DELETE':
		if ( access_has_bug_level( config_get( 'delete_bug_threshold' ), $t_bug_id ) ) {
			event_signal( 'EVENT_BUG_DELETED', array( $t_bug_id ) );
			bug_delete( $t_bug_id );
		} else {
			$t_failed_ids[$t_bug_id] = lang_get( 'bug_actiongroup_access' );
		}
		break;

	case 'MOVE':
		$f_project_id = gpc_get_int( 'project_id' );
		if ( access_has_bug_level( config_get( 'move_bug_threshold' ), $t_bug_id ) &&
		     access_has_project_level( config_get( 'report_bug_threshold' ), $f_project_id ) ) {
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,8 +136,8 @@
 
 	case 'MOVE':
 		$f_project_id = gpc_get_int( 'project_id' );
-		if ( access_has_bug_level( config_get( 'move_bug_threshold' ), $t_bug_id ) &&
-		     access_has_project_level( config_get( 'report_bug_threshold' ), $f_project_id ) ) {
+		if( access_has_bug_level( config_get( 'move_bug_threshold' ), $t_bug_id ) &&
+		    access_has_project_level( config_get( 'report_bug_threshold', null, null, $f_project_id ), $f_project_id ) ) {
 			/** @todo we need to issue a helper_call_custom_function( 'issue_update_validate', array( $t_bug_id, $t_bug_data, $f_bugnote_text ) ); */
 			bug_move( $t_bug_id, $f_project_id );
 			helper_call_custom_function( 'issue_update_notify', array( $t_bug_id ) );
```
