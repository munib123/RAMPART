# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4656_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4656_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 664-704 of the vulnerable file.

				/**
				 * Filter highlight color.
				 *
				 * @since 2.0.0
				 *
				 * @param string $gistpress_highlight_color Hex color code for highlighting lines.
				 *                                          Default is `#ffc`.
				 */
				'highlight_color'   => apply_filters( 'gistpress_highlight_color', '#ffc' ),
				'id'                => '',
				'lines'             => '',
				'lines_start'       => '',
				'show_line_numbers' => true,
				'show_meta'         => true,
				'oembed'            => 0, // Private use only.
			)
		);

		// Sanitize attributes.
		$attr = shortcode_atts( $defaults, $rawattr );
		$attr['embed_stylesheet']  = $this->shortcode_bool( $attr['embed_stylesheet'] );
		$attr['show_line_numbers'] = $this->shortcode_bool( $attr['show_line_numbers'] );
		$attr['show_meta']         = $this->shortcode_bool( $attr['show_meta'] );
		$attr['highlight']         = $this->parse_highlight_arg( $attr['highlight'] );
		$attr['lines']             = $this->parse_line_number_arg( $attr['lines'] );

		return $attr;
	}

	/**
	 * Try to determine the real file name from a sanitized file name.
	 *
	 * The new Gist "bookmark" URLs point to sanitized file names so that both
	 * hyphen and period in a file name show up as a hyphen e.g. a filename of
	 * foo.bar and foo-bar both appear in the bookmark URL as foo-bar. The
	 * correct original filenames are listed in the JSON data for the overall
	 * Gist, so this method does a call to that, and loops through the listed
	 * file names to see if it can determine which file was meant.
	 *
	 * If a Gist has two files that both resolve to the same sanitized filename,
	 * then we don't have any way to determine which one the other determined,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -681,6 +681,7 @@
 
 		// Sanitize attributes.
 		$attr = shortcode_atts( $defaults, $rawattr );
+		$attr['id']                = preg_replace( '/[^a-z0-9]+/i', '', $attr['id'] );
 		$attr['embed_stylesheet']  = $this->shortcode_bool( $attr['embed_stylesheet'] );
 		$attr['show_line_numbers'] = $this->shortcode_bool( $attr['show_line_numbers'] );
 		$attr['show_meta']         = $this->shortcode_bool( $attr['show_meta'] );
```
