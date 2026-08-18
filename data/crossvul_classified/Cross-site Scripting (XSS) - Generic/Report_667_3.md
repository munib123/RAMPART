# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 667_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `667_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

class AAL_Hook_Posts extends AAL_Hook_Base {
	
	protected function _draft_or_post_title( $post = 0 ) {
		$title = get_the_title( $post );
		
		if ( empty( $title ) )
			$title = __( '(no title)', 'aryo-activity-log' );
		
		return $title;
	}

	public function hooks_transition_post_status( $new_status, $old_status, $post ) {
		if ( 'auto-draft' === $old_status && ( 'auto-draft' !== $new_status && 'inherit' !== $new_status ) ) {
			// page created
			$action = 'created';
		}
		elseif ( 'auto-draft' === $new_status || ( 'new' === $old_status && 'inherit' === $new_status ) ) {
			// nvm.. ignore it.
			return;
		}
		elseif ( 'trash' === $new_status ) {
			// page was deleted.
			$action = 'trashed';
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 class AAL_Hook_Posts extends AAL_Hook_Base {
 	
 	protected function _draft_or_post_title( $post = 0 ) {
-		$title = get_the_title( $post );
+		$title = esc_html( get_the_title( $post ) );
 		
 		if ( empty( $title ) )
 			$title = __( '(no title)', 'aryo-activity-log' );
```
