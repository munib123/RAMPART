# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3354_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3354_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 138-178 of the vulnerable file.

			if ( ! current_user_can( get_post_type_object( 'customize_changeset' )->cap->publish_posts ) ) {
				$save_attrs['style'] = 'display: none';
			}
			submit_button( $save_text, 'primary save', 'save', false, $save_attrs );
			?>
			<span class="spinner"></span>
			<button type="button" class="customize-controls-preview-toggle">
				<span class="controls"><?php _e( 'Customize' ); ?></span>
				<span class="preview"><?php _e( 'Preview' ); ?></span>
			</button>
			<a class="customize-controls-close" href="<?php echo esc_url( $wp_customize->get_return_url() ); ?>">
				<span class="screen-reader-text"><?php _e( 'Close the Customizer and go back to the previous page' ); ?></span>
			</a>
		</div>

		<div id="widgets-right" class="wp-clearfix"><!-- For Widget Customizer, many widgets try to look for instances under div#widgets-right, so we have to add that ID to a container div in the Customizer for compat -->
		<div class="wp-full-overlay-sidebar-content" tabindex="-1">
			<div id="customize-info" class="accordion-section customize-info">
				<div class="accordion-section-title">
					<span class="preview-notice"><?php
						echo sprintf( __( 'You are customizing %s' ), '<strong class="panel-title site-title">' . get_bloginfo( 'name' ) . '</strong>' );
					?></span>
					<button type="button" class="customize-help-toggle dashicons dashicons-editor-help" aria-expanded="false"><span class="screen-reader-text"><?php _e( 'Help' ); ?></span></button>
				</div>
				<div class="customize-panel-description"><?php
					_e( 'The Customizer allows you to preview changes to your site before publishing them. You can navigate to different pages on your site within the preview. Edit shortcuts are shown for some editable elements.' );
				?></div>
			</div>

			<div id="customize-theme-controls">
				<ul class="customize-pane-parent"><?php // Panels and sections are managed here via JavaScript ?></ul>
			</div>
		</div>
		</div>

		<div id="customize-footer-actions" class="wp-full-overlay-footer">
			<button type="button" class="collapse-sidebar button" aria-expanded="true" aria-label="<?php echo esc_attr( _x( 'Hide Controls', 'label for hide controls button without length constraints' ) ); ?>">
				<span class="collapse-sidebar-arrow"></span>
				<span class="collapse-sidebar-label"><?php _ex( 'Hide Controls', 'short (~12 characters) label for hide controls button' ); ?></span>
			</button>
			<?php $previewable_devices = $wp_customize->get_previewable_devices(); ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,7 +155,7 @@
 			<div id="customize-info" class="accordion-section customize-info">
 				<div class="accordion-section-title">
 					<span class="preview-notice"><?php
-						echo sprintf( __( 'You are customizing %s' ), '<strong class="panel-title site-title">' . get_bloginfo( 'name' ) . '</strong>' );
+						echo sprintf( __( 'You are customizing %s' ), '<strong class="panel-title site-title">' . get_bloginfo( 'name', 'display' ) . '</strong>' );
 					?></span>
 					<button type="button" class="customize-help-toggle dashicons dashicons-editor-help" aria-expanded="false"><span class="screen-reader-text"><?php _e( 'Help' ); ?></span></button>
 				</div>
```
