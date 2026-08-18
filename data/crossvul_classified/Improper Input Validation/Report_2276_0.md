# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2276_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2276_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 294-334 of the vulnerable file.

       helper_duration_to_minutes( $t_bug_note->time_tracking ) > 0 ) ) {
	access_ensure_bug_level( config_get( 'add_bugnote_threshold' ), $f_bug_id );
	if ( !$t_bug_note->note &&
	     !config_get( 'time_tracking_without_note' ) ) {
		error_parameters( lang_get( 'bugnote' ) );
		trigger_error( ERROR_EMPTY_FIELD, ERROR );
	}
	if ( $t_bug_note->view_state !== config_get( 'default_bugnote_view_status' ) ) {
		access_ensure_bug_level( config_get( 'set_view_status_threshold' ), $f_bug_id );
	}
}

# Handle the reassign on feedback feature. Note that this feature generally
# won't work very well with custom workflows as it makes a lot of assumptions
# that may not be true. It assumes you don't have any statuses in the workflow
# between 'bug_submit_status' and 'bug_feedback_status'. It assumes you only
# have one feedback, assigned and submitted status.
if ( $t_bug_note->note &&
     config_get( 'reassign_on_feedback' ) &&
     $t_existing_bug->status === config_get( 'bug_feedback_status' ) &&
     $t_updated_bug->reporter_id === auth_get_current_user_id() ) {
	if ( $t_updated_bug->handler_id !== NO_USER ) {
		$t_updated_bug->status = config_get( 'bug_assigned_status' );
	} else {
		$t_updated_bug->status = config_get( 'bug_submit_status' );
	}
}

# Handle automatic assignment of issues.
if ( $t_existing_bug->handler_id === NO_USER &&
     $t_updated_bug->handler_id !== NO_USER &&
     $t_updated_bug->status < config_get( 'bug_assigned_status' ) &&
     config_get( 'auto_set_status_to_assigned' ) ) {
	$t_updated_bug->status = config_get( 'bug_assigned_status' );
}

# Allow a custom function to validate the proposed bug updates. Note that
# custom functions are being deprecated in MantisBT. You should migrate to
# the new plugin system instead.
helper_call_custom_function( 'issue_update_validate', array( $f_bug_id, $t_updated_bug, $t_bug_note->note ) );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -311,6 +311,7 @@
 if ( $t_bug_note->note &&
      config_get( 'reassign_on_feedback' ) &&
      $t_existing_bug->status === config_get( 'bug_feedback_status' ) &&
+     $t_updated_bug->handler_id !== auth_get_current_user_id() &&
      $t_updated_bug->reporter_id === auth_get_current_user_id() ) {
 	if ( $t_updated_bug->handler_id !== NO_USER ) {
 		$t_updated_bug->status = config_get( 'bug_assigned_status' );
```
