# CrossVul Fix Pair: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) in php
**Pair ID:** 4504_0
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**CWE:** CWE-80
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4504_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - This may allow such characters to be treated as control characters, which are executed client-side in the context of the user's session.

## Vulnerable Code
```php
Lines 3214-3254 of the vulnerable file.

	$quicktags_settings = array( 'buttons' => 'strong,em,link,block,del,ins,img,ul,ol,li,code,close' );
	$editor_args        = array(
		'textarea_name' => 'content',
		'textarea_rows' => 5,
		'media_buttons' => false,
		'tinymce'       => false,
		'quicktags'     => $quicktags_settings,
	);

	?>

	<label for="attachment_content" class="attachment-content-description"><strong><?php _e( 'Description' ); ?></strong>
	<?php

	if ( preg_match( '#^(audio|video)/#', $post->post_mime_type ) ) {
		echo ': ' . __( 'Displayed on attachment pages.' );
	}

	?>
	</label>
	<?php wp_editor( $post->post_content, 'attachment_content', $editor_args ); ?>

	</div>
	<?php

	$extras = get_compat_media_markup( $post->ID );
	echo $extras['item'];
	echo '<input type="hidden" id="image-edit-context" value="edit-attachment" />' . "\n";
}

/**
 * Displays non-editable attachment metadata in the publish meta box.
 *
 * @since 3.5.0
 */
function attachment_submitbox_metadata() {
	$post          = get_post();
	$attachment_id = $post->ID;

	$file     = get_attached_file( $attachment_id );
	$filename = esc_html( wp_basename( $file ) );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3231,7 +3231,7 @@
 
 	?>
 	</label>
-	<?php wp_editor( $post->post_content, 'attachment_content', $editor_args ); ?>
+	<?php wp_editor( format_to_edit( $post->post_content ), 'attachment_content', $editor_args ); ?>
 
 	</div>
 	<?php
```
