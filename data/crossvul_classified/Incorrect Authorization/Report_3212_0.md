# CrossVul Fix Pair: Incorrect Authorization in php
**Pair ID:** 3212_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3212_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```php
Lines 226-266 of the vulnerable file.

			wp_redirect( self_admin_url("plugins.php?deactivate-multi=true&plugin_status=$status&paged=$page&s=$s") );
			exit;

		case 'delete-selected':
			if ( ! current_user_can('delete_plugins') ) {
				wp_die(__('Sorry, you are not allowed to delete plugins for this site.'));
			}

			check_admin_referer('bulk-plugins');

			//$_POST = from the plugin form; $_GET = from the FTP details screen.
			$plugins = isset( $_REQUEST['checked'] ) ? (array) $_REQUEST['checked'] : array();
			if ( empty( $plugins ) ) {
				wp_redirect( self_admin_url("plugins.php?plugin_status=$status&paged=$page&s=$s") );
				exit;
			}

			$plugins = array_filter($plugins, 'is_plugin_inactive'); // Do not allow to delete Activated plugins.
			if ( empty( $plugins ) ) {
				wp_redirect( self_admin_url( "plugins.php?error=true&main=true&plugin_status=$status&paged=$page&s=$s" ) );
				exit;
			}

			include(ABSPATH . 'wp-admin/update.php');

			$parent_file = 'plugins.php';

			if ( ! isset($_REQUEST['verify-delete']) ) {
				wp_enqueue_script('jquery');
				require_once(ABSPATH . 'wp-admin/admin-header.php');
				?>
			<div class="wrap">
				<?php
					$plugin_info = array();
					$have_non_network_plugins = false;
					foreach ( (array) $plugins as $plugin ) {
						$plugin_slug = dirname( $plugin );

						if ( '.' == $plugin_slug ) {
							if ( $data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin ) ) {
								$plugin_info[ $plugin ] = $data;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -243,6 +243,14 @@
 			$plugins = array_filter($plugins, 'is_plugin_inactive'); // Do not allow to delete Activated plugins.
 			if ( empty( $plugins ) ) {
 				wp_redirect( self_admin_url( "plugins.php?error=true&main=true&plugin_status=$status&paged=$page&s=$s" ) );
+				exit;
+			}
+
+			// Bail on all if any paths are invalid.
+			// validate_file() returns truthy for invalid files
+			$invalid_plugin_files = array_filter( $plugins, 'validate_file' );
+			if ( $invalid_plugin_files ) {
+				wp_redirect( self_admin_url("plugins.php?plugin_status=$status&paged=$page&s=$s") );
 				exit;
 			}
 
```
