# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 4302_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4302_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 434-474 of the vulnerable file.

 * preview - true: the attachment should be previewable, otherwise false.
 * type - Can be "image", "text" or empty for other types.
 * alt - The alternate text to be associated with the icon.
 * icon - array with icon information, contains 'url' and 'alt' elements.
 * @param integer $p_bug_id A bug identifier.
 * @return array
 */
function file_get_visible_attachments( $p_bug_id ) {
	$t_attachment_rows = bug_get_attachments( $p_bug_id );
	$t_visible_attachments = array();

	$t_attachments_count = count( $t_attachment_rows );
	if( $t_attachments_count === 0 ) {
		return $t_visible_attachments;
	}

	$t_attachments = array();

	$t_preview_text_ext = config_get( 'preview_text_extensions' );
	$t_preview_image_ext = config_get( 'preview_image_extensions' );
	$t_attachments_view_threshold = config_get( 'view_attachments_threshold' );

	$t_image_previewed = false;
	for( $i = 0;$i < $t_attachments_count;$i++ ) {
		$t_row = $t_attachment_rows[$i];
		$t_user_id = (int)$t_row['user_id'];

		# This covers access checks for issue attachments
		if( !file_can_view_bug_attachments( $p_bug_id, $t_user_id ) ) {
			continue;
		}

		# This covers access checks for issue note attachments
		$t_attachment_note_id = (int)$t_row['bugnote_id'];
		if( $t_attachment_note_id !== 0 ) {
			if( bugnote_get_field( $t_attachment_note_id, 'view_state' ) != VS_PUBLIC ) {
				if( !access_has_bugnote_level( $t_attachments_view_threshold, $t_attachment_note_id ) ) {
					continue;
				}
			}
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -451,31 +451,21 @@
 
 	$t_preview_text_ext = config_get( 'preview_text_extensions' );
 	$t_preview_image_ext = config_get( 'preview_image_extensions' );
-	$t_attachments_view_threshold = config_get( 'view_attachments_threshold' );
 
 	$t_image_previewed = false;
-	for( $i = 0;$i < $t_attachments_count;$i++ ) {
-		$t_row = $t_attachment_rows[$i];
+	foreach( $t_attachment_rows as $t_row ) {
 		$t_user_id = (int)$t_row['user_id'];
-
-		# This covers access checks for issue attachments
-		if( !file_can_view_bug_attachments( $p_bug_id, $t_user_id ) ) {
+		$t_attachment_note_id = (int)$t_row['bugnote_id'];
+
+		if( !file_can_view_bug_attachments( $p_bug_id, $t_user_id )
+		|| !file_can_view_bugnote_attachments( $t_attachment_note_id, $t_user_id )
+		) {
 			continue;
-		}
-
-		# This covers access checks for issue note attachments
-		$t_attachment_note_id = (int)$t_row['bugnote_id'];
-		if( $t_attachment_note_id !== 0 ) {
-			if( bugnote_get_field( $t_attachment_note_id, 'view_state' ) != VS_PUBLIC ) {
-				if( !access_has_bugnote_level( $t_attachments_view_threshold, $t_attachment_note_id ) ) {
-					continue;
-				}
-			}
 		}
 
 		$t_id = (int)$t_row['id'];
 		$t_filename = $t_row['filename'];
-		$t_filesize = $t_row['filesize'];
+		$t_filesize = (int)$t_row['filesize'];
 		$t_diskfile = file_normalize_attachment_path( $t_row['diskfile'], bug_get_field( $p_bug_id, 'project_id' ) );
 		$t_date_added = $t_row['date_added'];
 
@@ -483,14 +473,14 @@
 		$t_attachment['id'] = $t_id;
 		$t_attachment['user_id'] = $t_user_id;
 		$t_attachment['display_name'] = file_get_display_name( $t_filename );
-		$t_attachment['size'] = (int)$t_filesize;
+		$t_attachment['size'] = $t_filesize;
 		$t_attachment['date_added'] = $t_date_added;
 		$t_attachment['diskfile'] = $t_diskfile;
 		$t_attachment['file_type'] = $t_row['file_type'];
-		$t_attachment['bugnote_id'] = (int)$t_row['bugnote_id'];
-
-		$t_attachment['can_download'] = file_can_download_bug_attachments( $p_bug_id, (int)$t_row['user_id'] );
-		$t_attachment['can_delete'] = file_can_delete_bug_attachments( $p_bug_id, (int)$t_row['user_id'] );
+		$t_attachment['bugnote_id'] = $t_attachment_note_id;
+
+		$t_attachment['can_download'] = file_can_download_bug_attachments( $p_bug_id, $t_user_id );
+		$t_attachment['can_delete'] = file_can_delete_bug_attachments( $p_bug_id, $t_user_id );
 
 		if( $t_attachment['can_download'] ) {
 			$t_attachment['download_url'] = 'file_download.php?file_id=' . $t_id . '&type=bug';
```
