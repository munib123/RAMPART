# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 878_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `878_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 278-318 of the vulnerable file.

	 */
	public static function get_page_info( $page_id, $type = 'post' ) {

		//Create Empty Object
		$arg      = array();
		$defaults = array(
			'link'      => '',
			'edit_link' => '',
			'object_id' => $page_id,
			'title'     => '-',
			'meta'      => array()
		);

		if ( ! empty( $type ) ) {
			switch ( $type ) {
				case "product":
				case "attachment":
				case "post":
				case "page":
					$arg = array(
						'title'     => get_the_title( $page_id ),
						'link'      => get_the_permalink( $page_id ),
						'edit_link' => get_edit_post_link( $page_id ),
						'meta'      => array(
							'post_type' => get_post_type( $page_id )
						)
					);
					break;
				case "category":
				case "post_tag":
				case "tax":
					$term = get_term( $page_id );
					$arg  = array(
						'title'     => $term->name,
						'link'      => ( is_wp_error( get_term_link( $page_id ) ) === true ? '' : get_term_link( $page_id ) ),
						'edit_link' => get_edit_term_link( $page_id ),
						'meta'      => array(
							'taxonomy'         => $term->taxonomy,
							'term_taxonomy_id' => $term->term_taxonomy_id,
							'count'            => $term->count,
						)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -295,7 +295,7 @@
 				case "post":
 				case "page":
 					$arg = array(
-						'title'     => get_the_title( $page_id ),
+						'title'     => esc_html( get_the_title( $page_id ) ),
 						'link'      => get_the_permalink( $page_id ),
 						'edit_link' => get_edit_post_link( $page_id ),
 						'meta'      => array(
@@ -308,7 +308,7 @@
 				case "tax":
 					$term = get_term( $page_id );
 					$arg  = array(
-						'title'     => $term->name,
+						'title'     => esc_html( $term->name ),
 						'link'      => ( is_wp_error( get_term_link( $page_id ) ) === true ? '' : get_term_link( $page_id ) ),
 						'edit_link' => get_edit_term_link( $page_id ),
 						'meta'      => array(
@@ -327,7 +327,7 @@
 				case "author":
 					$user_info = get_userdata( $page_id );
 					$arg       = array(
-						'title'     => ( $user_info->display_name != "" ? $user_info->display_name : $user_info->first_name . ' ' . $user_info->last_name ),
+						'title'     => ( $user_info->display_name != "" ? esc_html( $user_info->display_name ) : esc_html( $user_info->first_name . ' ' . $user_info->last_name ) ),
 						'link'      => get_author_posts_url( $page_id ),
 						'edit_link' => get_edit_user_link( $page_id ),
 					);
```
