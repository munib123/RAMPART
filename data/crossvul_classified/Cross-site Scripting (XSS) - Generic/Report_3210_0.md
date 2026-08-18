# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3210_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3210_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 3055-3095 of the vulnerable file.

	if ( ! empty( $data['video']['resolution_x'] ) )
		$metadata['width'] = (int) $data['video']['resolution_x'];
	if ( ! empty( $data['video']['resolution_y'] ) )
		$metadata['height'] = (int) $data['video']['resolution_y'];
	if ( ! empty( $data['fileformat'] ) )
		$metadata['fileformat'] = $data['fileformat'];
	if ( ! empty( $data['video']['dataformat'] ) )
		$metadata['dataformat'] = $data['video']['dataformat'];
	if ( ! empty( $data['video']['encoder'] ) )
		$metadata['encoder'] = $data['video']['encoder'];
	if ( ! empty( $data['video']['codec'] ) )
		$metadata['codec'] = $data['video']['codec'];

	if ( ! empty( $data['audio'] ) ) {
		unset( $data['audio']['streams'] );
		$metadata['audio'] = $data['audio'];
	}

	wp_add_id3_tag_data( $metadata, $data );

	return $metadata;
}

/**
 * Retrieve metadata from a audio file's ID3 tags
 *
 * @since 3.6.0
 *
 * @param string $file Path to file.
 * @return array|bool Returns array of metadata, if found.
 */
function wp_read_audio_metadata( $file ) {
	if ( ! file_exists( $file ) ) {
		return false;
	}
	$metadata = array();

	if ( ! defined( 'GETID3_TEMP_DIR' ) ) {
		define( 'GETID3_TEMP_DIR', get_temp_dir() );
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3072,6 +3072,8 @@
 
 	wp_add_id3_tag_data( $metadata, $data );
 
+	$metadata = wp_kses_post_deep( $metadata );
+
 	return $metadata;
 }
 
@@ -3117,6 +3119,8 @@
 
 	wp_add_id3_tag_data( $metadata, $data );
 
+	$metadata = wp_kses_post_deep( $metadata );
+
 	return $metadata;
 }
 
```
