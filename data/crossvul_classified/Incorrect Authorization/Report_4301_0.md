# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4301_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4301_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 201-241 of the vulnerable file.

function file_bug_has_attachments( $p_bug_id ) {
	if( file_bug_attachment_count( $p_bug_id ) > 0 ) {
		return true;
	} else {
		return false;
	}
}

/**
 * Check if the current user can view or download attachments.
 *
 * Generic call used by
 * - {@see file_can_view_bug_attachments()}
 * - {@see file_can_view_bugnote_attachments}
 * - {@see file_can_download_bug_attachments()}
 * - {@see file_can_download_bugnote_attachments}
 *
 * @param string   $p_action            'view' or 'download'
 * @param int      $p_bug_id            A bug identifier
 * @param int      $p_uploader_user_id  The user who uploaded the attachment
 *
 * @return bool
 *
 * @internal Should not be used outside of File API.
 */
function file_can_view_or_download( $p_action, $p_bug_id, $p_uploader_user_id ) {
	switch( $p_action ) {
		case 'view':
			$t_threshold_global = 'view_attachments_threshold';
			$t_threshold_own = 'allow_view_own_attachments';
			break;
		case 'download':
			$t_threshold_global = 'download_attachments_threshold';
			$t_threshold_own = 'allow_download_own_attachments';
			break;
		default:
			trigger_error( ERROR_GENERIC, ERROR );
	}

	$t_project_id = bug_get_field( $p_bug_id, 'project_id' );
	$t_access_global = config_get( $t_threshold_global,null, null, $t_project_id );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -218,12 +218,13 @@
  * @param string   $p_action            'view' or 'download'
  * @param int      $p_bug_id            A bug identifier
  * @param int      $p_uploader_user_id  The user who uploaded the attachment
+ * @param int|null $p_bugnote_id        If specified, will check at bugnote level
  *
  * @return bool
  *
  * @internal Should not be used outside of File API.
  */
-function file_can_view_or_download( $p_action, $p_bug_id, $p_uploader_user_id ) {
+function file_can_view_or_download( $p_action, $p_bug_id, $p_uploader_user_id, $p_bugnote_id = null ) {
 	switch( $p_action ) {
 		case 'view':
 			$t_threshold_global = 'view_attachments_threshold';
@@ -240,7 +241,11 @@
 	$t_project_id = bug_get_field( $p_bug_id, 'project_id' );
 	$t_access_global = config_get( $t_threshold_global,null, null, $t_project_id );
 
-	$t_can_access = access_has_bug_level( $t_access_global, $p_bug_id );
+	if( $p_bugnote_id === null ) {
+		$t_can_access = access_has_bug_level( $t_access_global, $p_bug_id );
+	} else {
+		$t_can_access = access_has_bugnote_level( $t_access_global, $p_bugnote_id );
+	}
 	if( $t_can_access ) {
 		return true;
 	}
@@ -263,6 +268,22 @@
 }
 
 /**
+ * Check if the current user can view attachments for the specified bug note.
+ *
+ * @param integer $p_bugnote_id       A bugnote identifier.
+ * @param integer $p_uploader_user_id The user who uploaded the attachment.
+ *
+ * @return boolean
+ */
+function file_can_view_bugnote_attachments( $p_bugnote_id, $p_uploader_user_id = null ) {
+	if( $p_bugnote_id == 0 ) {
+		return true;
+	}
+	$t_bug_id = bugnote_get_field( $p_bugnote_id, 'bug_id' );
+	return file_can_view_or_download( 'view', $t_bug_id, $p_uploader_user_id );
+}
+
+/**
  * Check if the current user can download attachments for the specified bug.
  *
  * @param integer $p_bug_id           A bug identifier.
@@ -272,6 +293,22 @@
  */
 function file_can_download_bug_attachments( $p_bug_id, $p_uploader_user_id = null ) {
 	return file_can_view_or_download( 'download', $p_bug_id, $p_uploader_user_id );
+}
+
+/**
+ * Check if the current user can download attachments for the specified bug note.
+ *
+ * @param integer $p_bugnote_id       A bugnote identifier.
+ * @param integer $p_uploader_user_id The user who uploaded the attachment.
+ *
+ * @return boolean
+ */
+function file_can_download_bugnote_attachments( $p_bugnote_id, $p_uploader_user_id = null ) {
+	if( $p_bugnote_id == 0 ) {
+		return true;
+	}
+	$t_bug_id = bugnote_get_field( $p_bugnote_id, 'bug_id' );
+	return file_can_view_or_download( 'download', $t_bug_id, $p_uploader_user_id, $p_bugnote_id );
 }
 
 /**
```
