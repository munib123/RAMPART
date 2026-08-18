# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3598_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3598_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 926-966 of the vulnerable file.

 *
 * @param string $p_username  The name of the user trying to delete the issue.
 * @param string $p_password  The password of the user.
 * @param integer $p_issue_id  The id of the issue to delete.
 * @return boolean  True if the issue has been deleted successfully, false otherwise.
 */
function mc_issue_delete( $p_username, $p_password, $p_issue_id ) {
	$t_user_id = mci_check_login( $p_username, $p_password );
	if( $t_user_id === false ) {
		return mci_soap_fault_login_failed();
	}

	if( !bug_exists( $p_issue_id ) ) {
		return new soap_fault( 'Client', '', "Issue '$p_issue_id' does not exist.");
	}

	$t_project_id = bug_get_field( $p_issue_id, 'project_id' );
	if( !mci_has_readwrite_access( $t_user_id, $t_project_id ) ) {
		return mci_soap_fault_access_denied( $t_user_id );
	}

	return bug_delete( $p_issue_id );
}

/**
 * Add a note to an existing issue.
 *
 * @param string $p_username  The name of the user trying to add a note to an issue.
 * @param string $p_password  The password of the user.
 * @param integer $p_issue_id  The id of the issue to add the note to.
 * @param IssueNoteData $p_note  The note to add.
 * @return integer The id of the added note.
 */
function mc_issue_note_add( $p_username, $p_password, $p_issue_id, $p_note ) {
	$t_user_id = mci_check_login( $p_username, $p_password );
	if( $t_user_id === false ) {
		return mci_soap_fault_login_failed();
	}

	if( (integer) $p_issue_id < 1 ) {
		return new soap_fault( 'Client', '', "Invalid issue id '$p_issue_id'" );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -943,6 +943,10 @@
 	if( !mci_has_readwrite_access( $t_user_id, $t_project_id ) ) {
 		return mci_soap_fault_access_denied( $t_user_id );
 	}
+	
+	if ( !access_has_bug_level( config_get( 'delete_bug_threshold' ), $p_issue_id, $t_user_id ) ) {
+	    return mci_soap_fault_access_denied( $t_user_id );
+	}
 
 	return bug_delete( $p_issue_id );
 }
```
