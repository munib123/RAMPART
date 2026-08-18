# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3672_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3672_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 47-75 of the vulnerable file.

	}
	if( !file_allow_bug_upload( $p_issue_id, $t_user_id ) ) {
		return mci_soap_fault_access_denied( $t_user_id );
	}
	if( !access_has_bug_level( config_get( 'upload_bug_file_threshold' ), $p_issue_id, $t_user_id ) ) {
		return mci_soap_fault_access_denied( $t_user_id );
	}
	return mci_file_add( $p_issue_id, $p_name, $p_content, $p_file_type, 'bug', '', '', $t_user_id );
}

/**
 * Delete an issue attachment given its id.
 *
 * @param string $p_username  The name of the user trying to add an attachment to an issue.
 * @param string $p_password  The password of the user.
 * @param integer $p_issue_attachment_id  The id of the attachment to be deleted.
 * @return true: success, false: failure
 */
function mc_issue_attachment_delete( $p_username, $p_password, $p_issue_attachment_id ) {
	$t_user_id = mci_check_login( $p_username, $p_password );
	if( $t_user_id === false ) {
		return mci_soap_fault_login_failed();
	}
	$t_bug_id = file_get_field( $p_issue_attachment_id, 'bug_id' );
	if( !access_has_bug_level( config_get( 'update_bug_threshold' ), $t_bug_id, $t_user_id ) ) {
		return mci_soap_fault_access_denied( $t_user_id );
	}
	return file_delete( $p_issue_attachment_id, 'bug' );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,12 +64,27 @@
  */
 function mc_issue_attachment_delete( $p_username, $p_password, $p_issue_attachment_id ) {
 	$t_user_id = mci_check_login( $p_username, $p_password );
+
 	if( $t_user_id === false ) {
 		return mci_soap_fault_login_failed();
 	}
+
 	$t_bug_id = file_get_field( $p_issue_attachment_id, 'bug_id' );
+
+	# Check access against update_bug_threshold
 	if( !access_has_bug_level( config_get( 'update_bug_threshold' ), $t_bug_id, $t_user_id ) ) {
 		return mci_soap_fault_access_denied( $t_user_id );
 	}
+
+	$t_attachment_owner = file_get_field( $f_file_id, 'user_id' );
+	$t_current_user_is_attachment_owner = $t_attachment_owner == $t_user_id;
+	# Factor in allow_delete_own_attachments=ON|OFF
+	if ( !$t_current_user_is_attachment_owner || ( $t_current_user_is_attachment_owner && !config_get( 'allow_delete_own_attachments' ) ) ) {
+		# Check access against delete_attachments_threshold
+		if ( !access_has_bug_level( config_get( 'delete_attachments_threshold' ), $t_bug_id, $t_user_id ) ) {
+			return mci_soap_fault_access_denied( $t_user_id );
+		}
+	}
+
 	return file_delete( $p_issue_attachment_id, 'bug' );
 }
```
