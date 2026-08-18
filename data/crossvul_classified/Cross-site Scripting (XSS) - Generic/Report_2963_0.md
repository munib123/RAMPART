# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2963_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2963_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 459-499 of the vulnerable file.

function rss_enclosure() {
	if ( post_password_required() )
		return;

	foreach ( (array) get_post_custom() as $key => $val) {
		if ($key == 'enclosure') {
			foreach ( (array) $val as $enc ) {
				$enclosure = explode("\n", $enc);

				// only get the first element, e.g. audio/mpeg from 'audio/mpeg mpga mp2 mp3'
				$t = preg_split('/[ \t]/', trim($enclosure[2]) );
				$type = $t[0];

				/**
				 * Filters the RSS enclosure HTML link tag for the current post.
				 *
				 * @since 2.2.0
				 *
				 * @param string $html_link_tag The HTML link tag with a URI and other attributes.
				 */
				echo apply_filters( 'rss_enclosure', '<enclosure url="' . trim( htmlspecialchars( $enclosure[0] ) ) . '" length="' . trim( $enclosure[1] ) . '" type="' . $type . '" />' . "\n" );
			}
		}
	}
}

/**
 * Display the atom enclosure for the current post.
 *
 * Uses the global $post to check whether the post requires a password and if
 * the user has the password for the post. If not then it will return before
 * displaying.
 *
 * Also uses the function get_post_custom() to get the post's 'enclosure'
 * metadata field and parses the value to display the enclosure(s). The
 * enclosure(s) consist of link HTML tag(s) with a URI and other attributes.
 *
 * @since 2.2.0
 */
function atom_enclosure() {
	if ( post_password_required() )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -476,7 +476,7 @@
 				 *
 				 * @param string $html_link_tag The HTML link tag with a URI and other attributes.
 				 */
-				echo apply_filters( 'rss_enclosure', '<enclosure url="' . trim( htmlspecialchars( $enclosure[0] ) ) . '" length="' . trim( $enclosure[1] ) . '" type="' . $type . '" />' . "\n" );
+				echo apply_filters( 'rss_enclosure', '<enclosure url="' . esc_url( trim( $enclosure[0] ) ) . '" length="' . absint( trim( $enclosure[1] ) ) . '" type="' . esc_attr( $type ) . '" />' . "\n" );
 			}
 		}
 	}
@@ -510,7 +510,7 @@
 				 *
 				 * @param string $html_link_tag The HTML link tag with a URI and other attributes.
 				 */
-				echo apply_filters( 'atom_enclosure', '<link href="' . trim( htmlspecialchars( $enclosure[0] ) ) . '" rel="enclosure" length="' . trim( $enclosure[1] ) . '" type="' . trim( $enclosure[2] ) . '" />' . "\n" );
+				echo apply_filters( 'atom_enclosure', '<link href="' . esc_url( trim( $enclosure[0] ) ) . '" rel="enclosure" length="' . absint( trim( $enclosure[1] ) ) . '" type="' . esc_attr( trim( $enclosure[2] ) ) . '" />' . "\n" );
 			}
 		}
 	}
```
