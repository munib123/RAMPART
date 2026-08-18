# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 5276_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5276_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 83-123 of the vulnerable file.

			// Save the data.
			$this->id = wp_insert_attachment( $object, $file['file'] );

			// Schedule a cleanup for 2 hours from now in case of failed install.
			wp_schedule_single_event( time() + 2 * HOUR_IN_SECONDS, 'upgrader_scheduled_cleanup', array( $this->id ) );

		} elseif ( is_numeric( $_GET[$urlholder] ) ) {
			// Numeric Package = previously uploaded file, see above.
			$this->id = (int) $_GET[$urlholder];
			$attachment = get_post( $this->id );
			if ( empty($attachment) )
				wp_die(__('Please select a file'));

			$this->filename = $attachment->post_title;
			$this->package = get_attached_file( $attachment->ID );
		} else {
			// Else, It's set to something, Back compat for plugins using the old (pre-3.3) File_Uploader handler.
			if ( ! ( ( $uploads = wp_upload_dir() ) && false === $uploads['error'] ) )
				wp_die( $uploads['error'] );

			$this->filename = $_GET[$urlholder];
			$this->package = $uploads['basedir'] . '/' . $this->filename;
		}
	}

	/**
	 * Delete the attachment/uploaded file.
	 *
	 * @since 3.2.2
	 * @access public
	 *
	 * @return bool Whether the cleanup was successful.
	 */
	public function cleanup() {
		if ( $this->id )
			wp_delete_attachment( $this->id );

		elseif ( file_exists( $this->package ) )
			return @unlink( $this->package );

		return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,8 +100,12 @@
 			if ( ! ( ( $uploads = wp_upload_dir() ) && false === $uploads['error'] ) )
 				wp_die( $uploads['error'] );
 
-			$this->filename = $_GET[$urlholder];
+			$this->filename = sanitize_file_name( $_GET[ $urlholder ] );
 			$this->package = $uploads['basedir'] . '/' . $this->filename;
+
+			if ( 0 !== strpos( realpath( $this->package ), realpath( $uploads['basedir'] ) ) ) {
+				wp_die( __( 'Please select a file' ) );
+			}
 		}
 	}
 
```
