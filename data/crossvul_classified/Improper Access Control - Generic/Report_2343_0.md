# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 2343_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2343_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 103-144 of the vulnerable file.

# Check if a specific bug has attachments
function file_bug_has_attachments( $p_bug_id ) {
	if( file_bug_attachment_count( $p_bug_id ) > 0 ) {
		return true;
	} else {
		return false;
	}
}

# Check if the current user can view attachments for the specified bug.
function file_can_view_bug_attachments( $p_bug_id, $p_uploader_user_id = null ) {
	$t_uploaded_by_me = auth_get_current_user_id() === $p_uploader_user_id;
	$t_can_view = access_has_bug_level( config_get( 'view_attachments_threshold' ), $p_bug_id );
	$t_can_view = $t_can_view || ( $t_uploaded_by_me && config_get( 'allow_view_own_attachments' ) );
	return $t_can_view;
}

# Check if the current user can download attachments for the specified bug.
function file_can_download_bug_attachments( $p_bug_id, $p_uploader_user_id = null ) {
	$t_uploaded_by_me = auth_get_current_user_id() === $p_uploader_user_id;
	$t_can_download = access_has_bug_level( config_get( 'download_attachments_threshold' ), $p_bug_id );
	$t_can_download = $t_can_download || ( $t_uploaded_by_me && config_get( 'allow_download_own_attachments' ) );
	return $t_can_download;
}

# Check if the current user can delete attachments from the specified bug.
function file_can_delete_bug_attachments( $p_bug_id, $p_uploader_user_id = null ) {
	if( bug_is_readonly( $p_bug_id ) ) {
		return false;
	}
	$t_uploaded_by_me = auth_get_current_user_id() === $p_uploader_user_id;
	$t_can_delete = access_has_bug_level( config_get( 'delete_attachments_threshold' ), $p_bug_id );
	$t_can_delete = $t_can_delete || ( $t_uploaded_by_me && config_get( 'allow_delete_own_attachments' ) );
	return $t_can_delete;
}

# Get icon corresponding to the specified filename
# returns an associative array with "url" and "alt" text.
function file_get_icon_url( $p_display_filename ) {
	$t_file_type_icons = config_get( 'file_type_icons' );

	$ext = utf8_strtolower( file_get_extension( $p_display_filename ) );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,8 +120,8 @@
 # Check if the current user can download attachments for the specified bug.
 function file_can_download_bug_attachments( $p_bug_id, $p_uploader_user_id = null ) {
 	$t_uploaded_by_me = auth_get_current_user_id() === $p_uploader_user_id;
-	$t_can_download = access_has_bug_level( config_get( 'download_attachments_threshold' ), $p_bug_id );
-	$t_can_download = $t_can_download || ( $t_uploaded_by_me && config_get( 'allow_download_own_attachments' ) );
+	$t_can_download = access_has_bug_level( config_get( 'download_attachments_threshold', null, null, bug_get_field( $p_bug_id, 'project_id' ) ), $p_bug_id );
+	$t_can_download = $t_can_download || ( $t_uploaded_by_me && config_get( 'allow_download_own_attachments', null, null, bug_get_field( $p_bug_id, 'project_id' ) ) );
 	return $t_can_download;
 }
 
```
