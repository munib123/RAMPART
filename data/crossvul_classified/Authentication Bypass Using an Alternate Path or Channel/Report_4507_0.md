# CrossVul Fix Pair: Authentication Bypass Using an Alternate Path or Channel in php
**Pair ID:** 4507_0
**Vulnerability Class:** Authentication Bypass Using an Alternate Path or Channel
**CWE:** CWE-288
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4507_0`)

## Vulnerability Information & PoC

## Description
Authentication Bypass Using an Alternate Path or Channel - A product requires authentication, but the product has an alternate path or channel that does not require authentication.

## Vulnerable Code
```php
Lines 669-709 of the vulnerable file.

			case 'users_per_page':
			case 'edit_comments_per_page':
			case 'upload_per_page':
			case 'edit_tags_per_page':
			case 'plugins_per_page':
			case 'export_personal_data_requests_per_page':
			case 'remove_personal_data_requests_per_page':
				// Network admin.
			case 'sites_network_per_page':
			case 'users_network_per_page':
			case 'site_users_network_per_page':
			case 'plugins_network_per_page':
			case 'themes_network_per_page':
			case 'site_themes_network_per_page':
				$value = (int) $value;
				if ( $value < 1 || $value > 999 ) {
					return;
				}
				break;
			default:
				/**
				 * Filters a screen option value before it is set.
				 *
				 * The filter can also be used to modify non-standard [items]_per_page
				 * settings. See the parent function for a full list of standard options.
				 *
				 * Returning false to the filter will skip saving the current option.
				 *
				 * @since 2.8.0
				 *
				 * @see set_screen_options()
				 *
				 * @param bool     $keep   Whether to save or skip saving the screen option value. Default false.
				 * @param string   $option The option name.
				 * @param int      $value  The number of rows to use.
				 */
				$value = apply_filters( 'set-screen-option', false, $option, $value ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores

				if ( false === $value ) {
					return;
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -686,23 +686,46 @@
 				}
 				break;
 			default:
+				if ( '_page' === substr( $option, -5 ) || 'layout_columns' === $option ) {
+					/**
+					 * Filters a screen option value before it is set.
+					 *
+					 * The filter can also be used to modify non-standard [items]_per_page
+					 * settings. See the parent function for a full list of standard options.
+					 *
+					 * Returning false to the filter will skip saving the current option.
+					 *
+					 * @since 2.8.0
+					 * @since 5.4.2 Only applied to options ending with '_page',
+					 *              or the 'layout_columns' option.
+					 *
+					 * @see set_screen_options()
+					 *
+					 * @param bool   $keep   Whether to save or skip saving the screen option value.
+					 *                       Default false.
+					 * @param string $option The option name.
+					 * @param int    $value  The number of rows to use.
+					 */
+					$value = apply_filters( 'set-screen-option', false, $option, $value ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores
+				}
+
 				/**
 				 * Filters a screen option value before it is set.
 				 *
-				 * The filter can also be used to modify non-standard [items]_per_page
-				 * settings. See the parent function for a full list of standard options.
+				 * The dynamic portion of the hook, `$option`, refers to the option name.
 				 *
 				 * Returning false to the filter will skip saving the current option.
 				 *
-				 * @since 2.8.0
+				 * @since 5.4.2
 				 *
 				 * @see set_screen_options()
 				 *
-				 * @param bool     $keep   Whether to save or skip saving the screen option value. Default false.
-				 * @param string   $option The option name.
-				 * @param int      $value  The number of rows to use.
+				 * @param bool   $keep   Whether to save or skip saving the screen option value.
+				 *                       Default false.
+				 * @param string $option The option name.
+				 * @param int    $value  The number of rows to use.
 				 */
-				$value = apply_filters( 'set-screen-option', false, $option, $value ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores
+				$value = apply_filters( "set_screen_option_{$option}", false, $option, $value );
 
 				if ( false === $value ) {
 					return;
```
