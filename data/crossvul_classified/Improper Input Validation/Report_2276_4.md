# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 2276_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2276_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 611-651 of the vulnerable file.

	$t_file_table = db_get_table( 'bug_file' );

	$query = "SELECT COUNT(*)
				  FROM $t_file_table
				  WHERE filename=" . db_param() . " AND bug_id=" . db_param();
	$result = db_query_bound( $query, Array( $p_name, $p_bug_id ) );
	$t_count = db_result( $result );

	if( $t_count > 0 ) {
		return false;
	} else {
		return true;
	}
}

/**
 * Add a file to the system using the configured storage method
 *
 * @param integer $p_bug_id the bug id
 * @param array $p_file the uploaded file info, as retrieved from gpc_get_file()
 */
function file_add( $p_bug_id, $p_file, $p_table = 'bug', $p_title = '', $p_desc = '', $p_user_id = null ) {

	file_ensure_uploaded( $p_file );
	$t_file_name = $p_file['name'];
	$t_tmp_file = $p_file['tmp_name'];

	if( !file_type_check( $t_file_name ) ) {
		trigger_error( ERROR_FILE_NOT_ALLOWED, ERROR );
	}

	if( !file_is_name_unique( $t_file_name, $p_bug_id ) ) {
		trigger_error( ERROR_DUPLICATE_FILE, ERROR );
	}

	if( 'bug' == $p_table ) {
		$t_project_id = bug_get_field( $p_bug_id, 'project_id' );
		$t_bug_id = bug_format_id( $p_bug_id );
	} else {
		$t_project_id = helper_get_current_project();
		$t_bug_id = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -628,12 +628,19 @@
  *
  * @param integer $p_bug_id the bug id
  * @param array $p_file the uploaded file info, as retrieved from gpc_get_file()
+ * @param string $p_table table ('bug' or 'doc')
+ * @param string $p_title file title
+ * @param string $p_desc file description
+ * @param int $p_user_id user id
+ * @param int $p_date_added date added
+ * @param bool $p_skip_bug_update skip bug last modification update (useful when importing bug attachments)
  */
-function file_add( $p_bug_id, $p_file, $p_table = 'bug', $p_title = '', $p_desc = '', $p_user_id = null ) {
+function file_add( $p_bug_id, $p_file, $p_table = 'bug', $p_title = '', $p_desc = '', $p_user_id = null, $p_date_added = 0, $p_skip_bug_update = false ) {
 
 	file_ensure_uploaded( $p_file );
 	$t_file_name = $p_file['name'];
 	$t_tmp_file = $p_file['tmp_name'];
+	$c_date_added = $p_date_added <= 0 ? db_now() : db_prepare_int( $p_date_added );
 
 	if( !file_type_check( $t_file_name ) ) {
 		trigger_error( ERROR_FILE_NOT_ALLOWED, ERROR );
@@ -728,13 +735,15 @@
 	$query = "INSERT INTO $t_file_table
 						(" . $p_table . "_id, title, description, diskfile, filename, folder, filesize, file_type, date_added, content, user_id)
 					  VALUES
-						($c_id, '$c_title', '$c_desc', '$c_unique_name', '$c_new_file_name', '$c_file_path', $c_file_size, '$c_file_type', '" . db_now() . "', $c_content, $c_user_id)";
+						($c_id, '$c_title', '$c_desc', '$c_unique_name', '$c_new_file_name', '$c_file_path', $c_file_size, '$c_file_type', '" . $c_date_added . "', $c_content, $c_user_id)";
 	db_query( $query );
 
 	if( 'bug' == $p_table ) {
 
 		# updated the last_updated date
-		$result = bug_update_date( $p_bug_id );
+		if ( !$p_skip_bug_update ) {
+			$result = bug_update_date( $p_bug_id );
+		}
 
 		# log new bug
 		history_log_event_special( $p_bug_id, FILE_ADDED, $t_file_name );
@@ -868,3 +877,103 @@
 	}
 	return $t_extension;
 }
+
+/**
+ * Get file content
+ *
+ * @param int $p_file_id file id
+ * @param string $p_type file type (either 'bug' or 'doc')
+ * @return array|bool array containing file type and content or false on failure to retrieve file
+ */
+function file_get_content( $p_file_id, $p_type = 'bug' ) {
+	# we handle the case where the file is attached to a bug
+	# or attached to a project as a project doc.
+	$query = '';
+	switch ( $p_type ) {
+		case 'bug':
+			$t_bug_file_table = db_get_table( 'mantis_bug_file_table' );
+			$query = "SELECT *
+				FROM $t_bug_file_table
+				WHERE id=" . db_param();
+			break;
+		case 'doc':
+			$t_project_file_table = db_get_table( 'mantis_project_file_table' );
+			$query = "SELECT *
+				FROM $t_project_file_table
+				WHERE id=" . db_param();
+			break;
+		default:
+			return false;
+	}
+	$result = db_query_bound( $query, Array( $p_file_id ) );
+	$row = db_fetch_array( $result );
+
+	if ( $f_type == 'bug' ) {
+		$t_project_id = bug_get_field( $row['bug_id'], 'project_id' );
+	} else {
+		$t_project_id = $row['bug_id'];
+	}
+
+	# If finfo is available (always true for PHP >= 5.3.0) we can use it to determine the MIME type of files
+	$finfo_available = false;
+	if ( class_exists( 'finfo' ) ) {
+		$t_info_file = config_get( 'fileinfo_magic_db_file' );
+
+		if ( is_blank( $t_info_file ) ) {
+			$finfo = new finfo( FILEINFO_MIME );
+		} else {
+			$finfo = new finfo( FILEINFO_MIME, $t_info_file );
+		}
+
+		if ( $finfo ) {
+			$finfo_available = true;
+		}
+	}
+
+	$t_content_type = $row['file_type'];
+
+	switch ( config_get( 'file_upload_method' ) ) {
+		case DISK:
+			$t_local_disk_file = file_normalize_attachment_path( $row['diskfile'], $t_project_id );
+
+			if ( file_exists( $t_local_disk_file ) ) {
+				if ( $finfo_available ) {
+					$t_file_info_type = $finfo->file( $t_local_disk_file );
+
+					if ( $t_file_info_type !== false ) {
+						$t_content_type = $t_file_info_type;
+					}
+				}
+				return array( 'type' => $t_content_type, 'content' => file_get_contents( $t_local_disk_file ) );
+			}
+			break;
+		case FTP:
+			$t_local_disk_file = file_normalize_attachment_path( $row['diskfile'], $t_project_id );
+
+			if ( !file_exists( $t_local_disk_file ) ) {
+				$ftp = file_ftp_connect();
+				file_ftp_get ( $ftp, $t_local_disk_file, $row['diskfile'] );
+				file_ftp_disconnect( $ftp );
+			}
+
+			if ( $finfo_available ) {
+				$t_file_info_type = $finfo->file( $t_local_disk_file );
+
+				if ( $t_file_info_type !== false ) {
+					$t_content_type = $t_file_info_type;
+				}
+			}
+			return array( 'type' => $t_content_type, 'content' => file_get_contents( $t_local_disk_file ) );
+			break;
+		default:
+			if ( $finfo_available ) {
+				$t_file_info_type = $finfo->buffer( $row['content'] );
+
+				if ( $t_file_info_type !== false ) {
+					$t_content_type = $t_file_info_type;
+				}
+			}
+			return array( 'type' => $t_content_type, 'content' => $row['content'] );
+			break;
+	}
+}
```
