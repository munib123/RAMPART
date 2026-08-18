# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3099_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3099_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 898-938 of the vulnerable file.

	}

	/**
	 *
	 * @global array $wp_meta_boxes
	 *
	 * @return bool
	 */
	public function show_screen_options() {
		global $wp_meta_boxes;

		if ( is_bool( $this->_show_screen_options ) )
			return $this->_show_screen_options;

		$columns = get_column_headers( $this );

		$show_screen = ! empty( $wp_meta_boxes[ $this->id ] ) || $columns || $this->get_option( 'per_page' );

		switch ( $this->base ) {
			case 'widgets':
				$this->_screen_settings = '<p><a id="access-on" href="widgets.php?widgets-access=on">' . __('Enable accessibility mode') . '</a><a id="access-off" href="widgets.php?widgets-access=off">' . __('Disable accessibility mode') . "</a></p>\n";
				break;
			case 'post' :
				$expand = '<fieldset class="editor-expand hidden"><legend>' . __( 'Additional settings' ) . '</legend><label for="editor-expand-toggle">';
				$expand .= '<input type="checkbox" id="editor-expand-toggle"' . checked( get_user_setting( 'editor_expand', 'on' ), 'on', false ) . ' />';
				$expand .= __( 'Enable full-height editor and distraction-free functionality.' ) . '</label></fieldset>';
				$this->_screen_settings = $expand;
				break;
			default:
				$this->_screen_settings = '';
				break;
		}

		/**
		 * Filters the screen settings text displayed in the Screen Options tab.
		 *
		 * This filter is currently only used on the Widgets screen to enable
		 * accessibility mode.
		 *
		 * @since 3.0.0
		 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -915,7 +915,8 @@
 
 		switch ( $this->base ) {
 			case 'widgets':
-				$this->_screen_settings = '<p><a id="access-on" href="widgets.php?widgets-access=on">' . __('Enable accessibility mode') . '</a><a id="access-off" href="widgets.php?widgets-access=off">' . __('Disable accessibility mode') . "</a></p>\n";
+				$nonce = wp_create_nonce( 'widgets-access' );
+				$this->_screen_settings = '<p><a id="access-on" href="widgets.php?widgets-access=on&_wpnonce=' . urlencode( $nonce ) . '">' . __('Enable accessibility mode') . '</a><a id="access-off" href="widgets.php?widgets-access=off&_wpnonce=' . urlencode( $nonce ) . '">' . __('Disable accessibility mode') . "</a></p>\n";
 				break;
 			case 'post' :
 				$expand = '<fieldset class="editor-expand hidden"><legend>' . __( 'Additional settings' ) . '</legend><label for="editor-expand-toggle">';
```
