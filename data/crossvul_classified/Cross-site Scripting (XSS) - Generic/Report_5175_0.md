# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5175_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5175_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 378-418 of the vulnerable file.

			);
			$link_end = '</a>';
		}

		$class = $thumb ? ' class="has-media-icon"' : '';
		?>
		<strong<?php echo $class; ?>>
			<?php
			echo $link_start;
			if ( $thumb ) : ?>
				<span class="media-icon <?php echo sanitize_html_class( $mime . '-icon' ); ?>"><?php echo $thumb; ?></span>
			<?php endif;
			echo $title . $link_end;
			_media_states( $post );
			?>
		</strong>
		<p class="filename">
			<span class="screen-reader-text"><?php _e( 'File name:' ); ?> </span>
			<?php
			$file = get_attached_file( $post->ID );
			echo wp_basename( $file );
			?>
		</p>
		<?php
	}

	/**
	 * Handles the author column output.
	 *
	 * @since 4.3.0
	 * @access public
	 *
	 * @param WP_Post $post The current WP_Post object.
	 */
	public function column_author( $post ) {
		printf( '<a href="%s">%s</a>',
			esc_url( add_query_arg( array( 'author' => get_the_author_meta('ID') ), 'upload.php' ) ),
			get_the_author()
		);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -395,7 +395,7 @@
 			<span class="screen-reader-text"><?php _e( 'File name:' ); ?> </span>
 			<?php
 			$file = get_attached_file( $post->ID );
-			echo wp_basename( $file );
+			echo esc_html( wp_basename( $file ) );
 			?>
 		</p>
 		<?php
```
