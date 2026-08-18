# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3671_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3671_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 1041-1085 of the vulnerable file.

	
	// mirrors check from bugnote_delete.php
	if ( ( $t_user_id != $t_reporter_id ) || ( OFF == config_get( 'bugnote_allow_user_edit_delete' ) ) ) {
	    if ( !access_has_bugnote_level( config_get( 'delete_bugnote_threshold' ), $p_issue_note_id ) ) {
	        return mci_soap_fault_access_denied( $t_user_id );
	    }
	}

	return bugnote_delete( $p_issue_note_id );
}

/**
 * Update a note
 *
 * @param string $p_username  The name of the user trying to add a note to an issue.
 * param string $p_password  The password of the user.
 * @param IssueNoteData $p_note  The note to update.
 * @return true on success, false on failure
 */
function mc_issue_note_update( $p_username, $p_password, $p_note ) {
    $t_user_id = mci_check_login( $p_username, $p_password );
    
    if( $t_user_id === false ) {
        return mci_soap_fault_login_failed();
    }

    if ( !isset( $p_note['id'] ) || is_blank( $p_note['id'] ) ) {
        return new soap_fault( 'Client', '', "Issue id must not be blank." );
    }
    
    if ( !isset( $p_note['text'] ) || is_blank( $p_note['text'] ) ) {
        return new soap_fault( 'Client', '', "Issue note text must not be blank." );
    }
    
    $t_issue_note_id = $p_note['id'];

    if( !bugnote_exists( $t_issue_note_id ) ) {
        return new soap_fault( 'Server', '', "Issue note '$t_issue_note_id' does not exist." );
    }
    
	$t_issue_id = bugnote_get_field( $t_issue_note_id, 'bug_id' );
	
	$t_project_id = bug_get_field( $t_issue_id, 'project_id' );

    if( !mci_has_readwrite_access( $t_user_id, $t_project_id ) ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1058,51 +1058,64 @@
  * @return true on success, false on failure
  */
 function mc_issue_note_update( $p_username, $p_password, $p_note ) {
-    $t_user_id = mci_check_login( $p_username, $p_password );
-    
-    if( $t_user_id === false ) {
-        return mci_soap_fault_login_failed();
-    }
-
-    if ( !isset( $p_note['id'] ) || is_blank( $p_note['id'] ) ) {
-        return new soap_fault( 'Client', '', "Issue id must not be blank." );
-    }
-    
-    if ( !isset( $p_note['text'] ) || is_blank( $p_note['text'] ) ) {
-        return new soap_fault( 'Client', '', "Issue note text must not be blank." );
-    }
-    
-    $t_issue_note_id = $p_note['id'];
-
-    if( !bugnote_exists( $t_issue_note_id ) ) {
-        return new soap_fault( 'Server', '', "Issue note '$t_issue_note_id' does not exist." );
-    }
-    
+	$t_user_id = mci_check_login( $p_username, $p_password );
+
+	if ( $t_user_id === false ) {
+		return mci_soap_fault_login_failed();
+	}
+
+	if ( !isset( $p_note['id'] ) || is_blank( $p_note['id'] ) ) {
+		return new soap_fault( 'Client', '', "Issue id must not be blank." );
+	}
+
+	if ( !isset( $p_note['text'] ) || is_blank( $p_note['text'] ) ) {
+		return new soap_fault( 'Client', '', "Issue note text must not be blank." );
+	}
+
+	$t_issue_note_id = $p_note['id'];
+
+	if ( !bugnote_exists( $t_issue_note_id ) ) {
+		return new soap_fault( 'Server', '', "Issue note '$t_issue_note_id' does not exist." );
+	}
+
 	$t_issue_id = bugnote_get_field( $t_issue_note_id, 'bug_id' );
-	
 	$t_project_id = bug_get_field( $t_issue_id, 'project_id' );
 
-    if( !mci_has_readwrite_access( $t_user_id, $t_project_id ) ) {
-        return mci_soap_fault_access_denied( $t_user_id );
-    }
-
-    if( !access_has_bug_level( config_get( 'add_bugnote_threshold' ), $t_issue_id, $t_user_id ) ) {
-        return mci_soap_fault_access_denied( $t_user_id, "You do not have access rights to add notes to this issue" );
-    }
-
-    if( bug_is_readonly( $t_issue_id ) ) {
-        return mci_soap_fault_access_denied( $t_user_id, "Issue ' . $t_issue_id . ' is readonly" );
-    }
-
-    if( isset( $p_note['view_state'] )) {
-        $t_view_state = $p_note['view_state'];
-        $t_view_state_id = mci_get_enum_id_from_objectref( 'view_state', $t_view_state );
-        bugnote_set_view_state( $t_issue_note_id, $t_view_state_id );
-    }
-
-    bugnote_set_text( $t_issue_note_id, $p_note['text'] );
-
-    return bugnote_date_update( $t_issue_note_id );
+	if ( !mci_has_readwrite_access( $t_user_id, $t_project_id ) ) {
+		return mci_soap_fault_access_denied( $t_user_id );
+	}
+
+	$t_issue_author_id = bugnote_get_field( $t_issue_note_id, 'reporter_id' );
+
+	# Check if the user owns the bugnote and is allowed to update their own bugnotes
+	# regardless of the update_bugnote_threshold level.
+	$t_user_owns_the_bugnote = bugnote_is_user_reporter( $t_issue_note_id, $t_user_id );
+	$t_user_can_update_own_bugnote = config_get( 'bugnote_allow_user_edit_delete', null, $t_user_id, $t_project_id );
+	if ( $t_user_owns_the_bugnote && !$t_user_can_update_own_bugnote ) {
+		return mci_soap_fault_access_denied( $t_user_id );
+	}
+
+	# Check if the user has an access level beyond update_bugnote_threshold for the
+	# project containing the bugnote to update.
+	$t_update_bugnote_threshold = config_get( 'update_bugnote_threshold', null, $t_user_id, $t_project_id );
+	if ( !$t_user_owns_the_bugnote && !access_has_bugnote_level( $t_update_bugnote_threshold, $t_user_id, $t_project_id ) ) {
+		return mci_soap_fault_access_denied( $t_user_id );
+	}
+
+	# Check if the bug is readonly
+	if ( bug_is_readonly( $t_issue_id ) ) {
+		return mci_soap_fault_access_denied( $t_user_id, "Issue ' . $t_issue_id . ' is readonly" );
+	}
+
+	if ( isset( $p_note['view_state'] ) ) {
+		$t_view_state = $p_note['view_state'];
+		$t_view_state_id = mci_get_enum_id_from_objectref( 'view_state', $t_view_state );
+		bugnote_set_view_state( $t_issue_note_id, $t_view_state_id );
+	}
+
+	bugnote_set_text( $t_issue_note_id, $p_note['text'] );
+
+	return bugnote_date_update( $t_issue_note_id );
 }
 
 /**
```
