# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1117_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1117_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 226-266 of the vulnerable file.

add_filter( 'the_author', 'ent2ncr', 8 );
add_filter( 'the_guid', 'esc_url' );

// Email filters
add_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );

// Mark site as no longer fresh
foreach ( array( 'publish_post', 'publish_page', 'wp_ajax_save-widget', 'wp_ajax_widgets-order', 'customize_save_after' ) as $action ) {
	add_action( $action, '_delete_option_fresh_site', 0 );
}

// Misc filters
add_filter( 'option_ping_sites', 'privacy_ping_filter' );
add_filter( 'option_blog_charset', '_wp_specialchars' ); // IMPORTANT: This must not be wp_specialchars() or esc_html() or it'll cause an infinite loop
add_filter( 'option_blog_charset', '_canonical_charset' );
add_filter( 'option_home', '_config_wp_home' );
add_filter( 'option_siteurl', '_config_wp_siteurl' );
add_filter( 'tiny_mce_before_init', '_mce_set_direction' );
add_filter( 'teeny_mce_before_init', '_mce_set_direction' );
add_filter( 'pre_kses', 'wp_pre_kses_less_than' );
add_filter( 'sanitize_title', 'sanitize_title_with_dashes', 10, 3 );
add_action( 'check_comment_flood', 'check_comment_flood_db', 10, 4 );
add_filter( 'comment_flood_filter', 'wp_throttle_comment_flood', 10, 3 );
add_filter( 'pre_comment_content', 'wp_rel_ugc', 15 );
add_filter( 'comment_email', 'antispambot' );
add_filter( 'option_tag_base', '_wp_filter_taxonomy_base' );
add_filter( 'option_category_base', '_wp_filter_taxonomy_base' );
add_filter( 'the_posts', '_close_comments_for_old_posts', 10, 2 );
add_filter( 'comments_open', '_close_comments_for_old_post', 10, 2 );
add_filter( 'pings_open', '_close_comments_for_old_post', 10, 2 );
add_filter( 'editable_slug', 'urldecode' );
add_filter( 'editable_slug', 'esc_textarea' );
add_filter( 'nav_menu_meta_box_object', '_wp_nav_menu_meta_box_object' );
add_filter( 'pingback_ping_source_uri', 'pingback_ping_source_uri' );
add_filter( 'xmlrpc_pingback_error', 'xmlrpc_pingback_error' );
add_filter( 'title_save_pre', 'trim' );

add_action( 'transition_comment_status', '_clear_modified_cache_on_transition_comment_status', 10, 2 );

add_filter( 'http_request_host_is_external', 'allowed_http_request_hosts', 10, 2 );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -243,6 +243,7 @@
 add_filter( 'tiny_mce_before_init', '_mce_set_direction' );
 add_filter( 'teeny_mce_before_init', '_mce_set_direction' );
 add_filter( 'pre_kses', 'wp_pre_kses_less_than' );
+add_filter( 'pre_kses', 'wp_pre_kses_block_attributes', 10, 3 );
 add_filter( 'sanitize_title', 'sanitize_title_with_dashes', 10, 3 );
 add_action( 'check_comment_flood', 'check_comment_flood_db', 10, 4 );
 add_filter( 'comment_flood_filter', 'wp_throttle_comment_flood', 10, 3 );
```
