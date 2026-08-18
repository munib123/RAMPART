# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3670_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3670_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1096-1136 of the vulnerable file.

	$t_issue_id = bugnote_get_field( $t_issue_note_id, 'bug_id' );
	$t_project_id = bug_get_field( $t_issue_id, 'project_id' );

	if ( !mci_has_readwrite_access( $t_user_id, $t_project_id ) ) {
		return mci_soap_fault_access_denied( $t_user_id );
	}

	$t_issue_author_id = bugnote_get_field( $t_issue_note_id, 'reporter_id' );

	# Check if the user owns the bugnote and is allowed to update their own bugnotes
	# regardless of the update_bugnote_threshold level.
	$t_user_owns_the_bugnote = bugnote_is_user_reporter( $t_issue_note_id, $t_user_id );
	$t_user_can_update_own_bugnote = config_get( 'bugnote_allow_user_edit_delete', null, $t_user_id, $t_project_id );
	if ( $t_user_owns_the_bugnote && !$t_user_can_update_own_bugnote ) {
		return mci_soap_fault_access_denied( $t_user_id );
	}

	# Check if the user has an access level beyond update_bugnote_threshold for the
	# project containing the bugnote to update.
	$t_update_bugnote_threshold = config_get( 'update_bugnote_threshold', null, $t_user_id, $t_project_id );
	if ( !$t_user_owns_the_bugnote && !access_has_bugnote_level( $t_update_bugnote_threshold, $t_user_id, $t_project_id ) ) {
		return mci_soap_fault_access_denied( $t_user_id );
	}

	# Check if the bug is readonly
	if ( bug_is_readonly( $t_issue_id ) ) {
		return mci_soap_fault_access_denied( $t_user_id, "Issue ' . $t_issue_id . ' is readonly" );
	}

	if ( isset( $p_note['view_state'] ) ) {
		$t_view_state = $p_note['view_state'];
		$t_view_state_id = mci_get_enum_id_from_objectref( 'view_state', $t_view_state );
		bugnote_set_view_state( $t_issue_note_id, $t_view_state_id );
	}

	bugnote_set_text( $t_issue_note_id, $p_note['text'] );

	return bugnote_date_update( $t_issue_note_id );
}

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1113,7 +1113,7 @@
 	# Check if the user has an access level beyond update_bugnote_threshold for the
 	# project containing the bugnote to update.
 	$t_update_bugnote_threshold = config_get( 'update_bugnote_threshold', null, $t_user_id, $t_project_id );
-	if ( !$t_user_owns_the_bugnote && !access_has_bugnote_level( $t_update_bugnote_threshold, $t_user_id, $t_project_id ) ) {
+	if ( !$t_user_owns_the_bugnote && !access_has_bugnote_level( $t_update_bugnote_threshold, $t_issue_note_id, $t_user_id ) ) {
 		return mci_soap_fault_access_denied( $t_user_id );
 	}
 
```
