# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2362_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2362_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 113-153 of the vulnerable file.

	http_security_headers();

	# Make sure that IE can download the attachments under https.
	header( 'Pragma: public' );

	# To fix an IE bug which causes problems when downloading
	# attached files via HTTPS, we disable the "Pragma: no-cache"
	# command when IE is used over HTTPS.
	global $g_allow_file_cache;
	if ( http_is_protocol_https() && is_browser_internet_explorer() ) {
		# Suppress "Pragma: no-cache" header.
	} else {
		if ( !isset( $g_allow_file_cache ) ) {
		    header( 'Pragma: no-cache' );
		}
	}
	header( 'Expires: ' . gmdate( 'D, d M Y H:i:s \G\M\T', time() ) );

	header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s \G\M\T', $v_date_added ) );

	$t_filename = file_get_display_name( $v_filename );
	# For Internet Explorer 8 as per http://blogs.msdn.com/ie/archive/2008/07/02/ie8-security-part-v-comprehensive-protection.aspx
	# Don't let IE second guess our content-type!
	header( 'X-Content-Type-Options: nosniff' );

	http_content_disposition_header( $t_filename, $f_show_inline );

	header( 'Content-Length: ' . $v_filesize );

	# If finfo is available (always true for PHP >= 5.3.0) we can use it to determine the MIME type of files
	$finfo = finfo_get_if_available();

	$t_content_type = $v_file_type;

	$t_content_type_override = file_get_content_type_override ( $t_filename );

	# dump file content to the connection.
	switch ( config_get( 'file_upload_method' ) ) {
		case DISK:
			$t_local_disk_file = file_normalize_attachment_path( $v_diskfile, $t_project_id );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,14 +130,10 @@
 
 	header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s \G\M\T', $v_date_added ) );
 
+	$t_upload_method = config_get( 'file_upload_method' );
 	$t_filename = file_get_display_name( $v_filename );
-	# For Internet Explorer 8 as per http://blogs.msdn.com/ie/archive/2008/07/02/ie8-security-part-v-comprehensive-protection.aspx
-	# Don't let IE second guess our content-type!
-	header( 'X-Content-Type-Options: nosniff' );
-
-	http_content_disposition_header( $t_filename, $f_show_inline );
-
-	header( 'Content-Length: ' . $v_filesize );
+
+	# Content headers
 
 	# If finfo is available (always true for PHP >= 5.3.0) we can use it to determine the MIME type of files
 	$finfo = finfo_get_if_available();
@@ -145,27 +141,13 @@
 	$t_content_type = $v_file_type;
 
 	$t_content_type_override = file_get_content_type_override ( $t_filename );
-
-	# dump file content to the connection.
-	switch ( config_get( 'file_upload_method' ) ) {
+	$t_file_info_type = false;
+
+	switch( $t_upload_method ) {
 		case DISK:
 			$t_local_disk_file = file_normalize_attachment_path( $v_diskfile, $t_project_id );
-
-			if ( file_exists( $t_local_disk_file ) ) {
-				if ( $finfo ) {
-					$t_file_info_type = $finfo->file( $t_local_disk_file );
-
-					if ( $t_file_info_type !== false ) {
-						$t_content_type = $t_file_info_type;
-					}
-				}
-
-				if ( $t_content_type_override ) {
-					$t_content_type = $t_content_type_override;
-				}
-
-				header( 'Content-Type: ' . $t_content_type );
-				readfile( $t_local_disk_file );
+			if( file_exists( $t_local_disk_file ) && $finfo ) {
+				$t_file_info_type = $finfo->file( $t_local_disk_file );
 			}
 			break;
 		case FTP:
@@ -179,32 +161,42 @@
 
 			if ( $finfo ) {
 				$t_file_info_type = $finfo->file( $t_local_disk_file );
-
-				if ( $t_file_info_type !== false ) {
-					$t_content_type = $t_file_info_type;
-				}
-			}
-
-			if ( $t_content_type_override ) {
-				$t_content_type = $t_content_type_override;
-			}
-
-			header( 'Content-Type: ' . $t_content_type );
-			readfile( $t_local_disk_file );
-			break;
-		default:
+			}
+			break;
+		case DATABASE:
 			if ( $finfo ) {
 				$t_file_info_type = $finfo->buffer( $v_content );
-
-				if ( $t_file_info_type !== false ) {
-					$t_content_type = $t_file_info_type;
-				}
-			}
-
-			if ( $t_content_type_override ) {
-				$t_content_type = $t_content_type_override;
-			}
-
-			header( 'Content-Type: ' . $t_content_type );
+			}
+	}
+
+	if( $t_file_info_type !== false ) {
+		$t_content_type = $t_file_info_type;
+	}
+
+	if( $t_content_type_override ) {
+		$t_content_type = $t_content_type_override;
+	}
+
+	# Don't allow inline flash
+	if( false !== strpos( $t_content_type, 'application/x-shockwave-flash' ) ) {
+		http_content_disposition_header( $t_filename );
+	} else {
+		http_content_disposition_header( $t_filename, $f_show_inline );
+	}
+
+	header( 'Content-Type: ' . $t_content_type );
+	header( 'Content-Length: ' . $v_filesize );
+
+	# For Internet Explorer 8 as per http://blogs.msdn.com/ie/archive/2008/07/02/ie8-security-part-v-comprehensive-protection.aspx
+	# Don't let IE second guess our content-type!
+	header( 'X-Content-Type-Options: nosniff' );
+
+	# dump file content to the connection.
+	switch( $t_upload_method ) {
+		case DISK:
+		case FTP:
+			readfile( $t_local_disk_file );
+			break;
+		case DATABASE:
 			echo $v_content;
 	}
```
