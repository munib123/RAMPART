# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 667_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `667_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

class AAL_Hook_Comments extends AAL_Hook_Base {
	
	protected function _add_comment_log( $id, $action, $comment = null ) {
		if ( is_null( $comment ) )
			$comment = get_comment( $id );
		
		aal_insert_log( array(
			'action'         => $action,
			'object_type'    => 'Comments',
			'object_subtype' => get_post_type( $comment->comment_post_ID ),
			'object_name'    => get_the_title( $comment->comment_post_ID ),
			'object_id'      => $id,
		) );
	}
	
	public function handle_comment_log( $comment_ID, $comment = null ) {
		if ( is_null( $comment ) )
			$comment = get_comment( $comment_ID );
		
		$action = 'created';
		switch ( current_filter() ) {
			case 'wp_insert_comment' :
				$action = 1 === (int) $comment->comment_approved ? 'approved' : 'pending';
				break;
			
			case 'edit_comment' :
				$action = 'updated';
				break;

			case 'delete_comment' :
				$action = 'deleted';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,7 @@
 			'action'         => $action,
 			'object_type'    => 'Comments',
 			'object_subtype' => get_post_type( $comment->comment_post_ID ),
-			'object_name'    => get_the_title( $comment->comment_post_ID ),
+			'object_name'    => esc_html( get_the_title( $comment->comment_post_ID ) ),
 			'object_id'      => $id,
 		) );
 	}
```
