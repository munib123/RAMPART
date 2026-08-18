# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 1699_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1699_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 5217-5258 of the vulnerable file.


		$post_more = isset( $content_struct['mt_text_more'] ) ? $content_struct['mt_text_more'] : null;

		$post_status = $publish ? 'publish' : 'draft';
		if ( isset( $content_struct["{$post_type}_status"] ) ) {
			switch( $content_struct["{$post_type}_status"] ) {
				case 'draft':
				case 'pending':
				case 'private':
				case 'publish':
					$post_status = $content_struct["{$post_type}_status"];
					break;
				default:
					$post_status = $publish ? 'publish' : 'draft';
					break;
			}
		}

		$tags_input = isset( $content_struct['mt_keywords'] ) ? $content_struct['mt_keywords'] : null;

		if ( ('publish' == $post_status) ) {
			if ( ( 'page' == $post_type ) && ! current_user_can( 'publish_pages' ) ) {
				return new IXR_Error( 401, __( 'Sorry, you do not have the right to publish this page.' ) );
			} elseif ( ! current_user_can( 'publish_posts' ) ) {
				return new IXR_Error( 401, __( 'Sorry, you do not have the right to publish this post.' ) );
			}
		}

		if ( $post_more )
			$post_content = $post_content . "<!--more-->" . $post_more;

		$to_ping = null;
		if ( isset( $content_struct['mt_tb_ping_urls'] ) ) {
			$to_ping = $content_struct['mt_tb_ping_urls'];
			if ( is_array($to_ping) )
				$to_ping = implode(' ', $to_ping);
		}

		// Do some timestamp voodoo.
		if ( !empty( $content_struct['date_created_gmt'] ) )
			// We know this is supposed to be GMT, so we're going to slap that Z on there by force.
			$dateCreated = rtrim( $content_struct['date_created_gmt']->getIso(), 'Z' ) . 'Z';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5234,8 +5234,8 @@
 
 		$tags_input = isset( $content_struct['mt_keywords'] ) ? $content_struct['mt_keywords'] : null;
 
-		if ( ('publish' == $post_status) ) {
-			if ( ( 'page' == $post_type ) && ! current_user_can( 'publish_pages' ) ) {
+		if ( 'publish' == $post_status || 'private' == $post_status ) {
+			if ( 'page' == $post_type && ! current_user_can( 'publish_pages' ) ) {
 				return new IXR_Error( 401, __( 'Sorry, you do not have the right to publish this page.' ) );
 			} elseif ( ! current_user_can( 'publish_posts' ) ) {
 				return new IXR_Error( 401, __( 'Sorry, you do not have the right to publish this post.' ) );
```
