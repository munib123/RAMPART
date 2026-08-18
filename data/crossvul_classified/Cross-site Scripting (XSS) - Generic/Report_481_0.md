# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 481_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `481_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2332-2372 of the vulnerable file.

				if ( $new_filename != $filename ) {
					$proper_filename = $new_filename; // Mark that it changed
				}
				// Redefine the extension / MIME
				$wp_filetype = wp_check_filetype( $new_filename, $mimes );
				$ext = $wp_filetype['ext'];
				$type = $wp_filetype['type'];
			} else {
				// Reset $real_mime and try validating again.
				$real_mime = false;
			}
		}
	}

	// Validate files that didn't get validated during previous checks.
	if ( $type && ! $real_mime && extension_loaded( 'fileinfo' ) ) {
		$finfo = finfo_open( FILEINFO_MIME_TYPE );
		$real_mime = finfo_file( $finfo, $file );
		finfo_close( $finfo );

		/*
		 * If $real_mime doesn't match what we're expecting, we need to do some extra
		 * vetting of application mime types to make sure this type of file is allowed.
		 * Other mime types are assumed to be safe, but should be considered unverified.
		 */
		if ( $real_mime && ( $real_mime !== $type ) && ( 0 === strpos( $real_mime, 'application' ) ) ) {
			$allowed = get_allowed_mime_types();

			if ( ! in_array( $real_mime, $allowed ) ) {
				$type = $ext = false;
			}
		}
	}

	/**
	 * Filters the "real" file type of the given file.
	 *
	 * @since 3.0.0
	 *
	 * @param array  $wp_check_filetype_and_ext File data array containing 'ext', 'type', and
	 *                                          'proper_filename' keys.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2349,17 +2349,52 @@
 		$real_mime = finfo_file( $finfo, $file );
 		finfo_close( $finfo );
 
+		// fileinfo often misidentifies obscure files as one of these types
+		$nonspecific_types = array(
+			'application/octet-stream',
+			'application/encrypted',
+			'application/CDFV2-encrypted',
+			'application/zip',
+		);
+
 		/*
-		 * If $real_mime doesn't match what we're expecting, we need to do some extra
-		 * vetting of application mime types to make sure this type of file is allowed.
-		 * Other mime types are assumed to be safe, but should be considered unverified.
+		 * If $real_mime doesn't match the content type we're expecting from the file's extension,
+		 * we need to do some additional vetting. Media types and those listed in $nonspecific_types are
+		 * allowed some leeway, but anything else must exactly match the real content type.
 		 */
-		if ( $real_mime && ( $real_mime !== $type ) && ( 0 === strpos( $real_mime, 'application' ) ) ) {
-			$allowed = get_allowed_mime_types();
-
-			if ( ! in_array( $real_mime, $allowed ) ) {
+		if ( in_array( $real_mime, $nonspecific_types, true ) ) {
+			// File is a non-specific binary type. That's ok if it's a type that generally tends to be binary.
+			if ( !in_array( substr( $type, 0, strcspn( $type, '/' ) ), array( 'application', 'video', 'audio' ) ) ) {
 				$type = $ext = false;
 			}
+		} elseif ( 0 === strpos( $real_mime, 'video/' ) || 0 === strpos( $real_mime, 'audio/' ) ) {
+			/*
+			 * For these types, only the major type must match the real value.
+			 * This means that common mismatches are forgiven: application/vnd.apple.numbers is often misidentified as application/zip,
+			 * and some media files are commonly named with the wrong extension (.mov instead of .mp4)
+			 */
+
+			if ( substr( $real_mime, 0, strcspn( $real_mime, '/' ) ) !== substr( $type, 0, strcspn( $type, '/' ) ) ) {
+				$type = $ext = false;
+			}
+		} else {
+			if ( $type !== $real_mime ) {
+				/*
+				 * Everything else including image/* and application/*: 
+				 * If the real content type doesn't match the file extension, assume it's dangerous.
+				 */
+				$type = $ext = false;
+			}
+
+		}
+	}
+
+	// The mime type must be allowed 
+	if ( $type ) {
+		$allowed = get_allowed_mime_types();
+
+		if ( ! in_array( $type, $allowed ) ) {
+			$type = $ext = false;
 		}
 	}
 
```
