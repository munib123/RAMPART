# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 3672_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3672_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 27-53 of the vulnerable file.

	  */
	require_once( 'core.php' );

	require_once( 'file_api.php' );

	form_security_validate( 'bug_file_delete' );

	$f_file_id = gpc_get_int( 'file_id' );

	$t_bug_id = file_get_field( $f_file_id, 'bug_id' );

	$t_bug = bug_get( $t_bug_id, true );
	if( $t_bug->project_id != helper_get_current_project() ) {
		# in case the current project is not the same project of the bug we are viewing...
		# ... override the current project. This to avoid problems with categories and handlers lists etc.
		$g_project_override = $t_bug->project_id;
	}

	access_ensure_bug_level( config_get( 'update_bug_threshold' ), $t_bug_id );

	helper_ensure_confirmed( lang_get( 'delete_attachment_sure_msg' ), lang_get( 'delete_attachment_button' ) );

	file_delete( $f_file_id, 'bug' );

	form_security_purge( 'bug_file_delete' );

	print_header_redirect_view( $t_bug_id );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,6 +44,12 @@
 
 	access_ensure_bug_level( config_get( 'update_bug_threshold' ), $t_bug_id );
 
+	$t_attachment_owner = file_get_field( $f_file_id, 'user_id' );
+	$t_current_user_is_attachment_owner = $t_attachment_owner == auth_get_current_user_id();
+	if ( !$t_current_user_is_attachment_owner || ( $t_current_user_is_attachment_owner && !config_get( 'allow_delete_own_attachments' ) ) ) {
+		access_ensure_bug_level( config_get( 'delete_attachments_threshold'), $t_bug_id );
+	}
+
 	helper_ensure_confirmed( lang_get( 'delete_attachment_sure_msg' ), lang_get( 'delete_attachment_button' ) );
 
 	file_delete( $f_file_id, 'bug' );
```
