# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5176_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5176_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 2761-2801 of the vulnerable file.

	 */
	do_action( 'heartbeat_tick', $response, $screen_id );

	// Send the current time according to the server
	$response['server_time'] = time();

	wp_send_json( $response );
}

/**
 * Ajax handler for getting revision diffs.
 *
 * @since 3.6.0
 */
function wp_ajax_get_revision_diffs() {
	require ABSPATH . 'wp-admin/includes/revision.php';

	if ( ! $post = get_post( (int) $_REQUEST['post_id'] ) )
		wp_send_json_error();

	if ( ! current_user_can( 'read_post', $post->ID ) )
		wp_send_json_error();

	// Really just pre-loading the cache here.
	if ( ! $revisions = wp_get_post_revisions( $post->ID, array( 'check_enabled' => false ) ) )
		wp_send_json_error();

	$return = array();
	@set_time_limit( 0 );

	foreach ( $_REQUEST['compare'] as $compare_key ) {
		list( $compare_from, $compare_to ) = explode( ':', $compare_key ); // from:to

		$return[] = array(
			'id' => $compare_key,
			'fields' => wp_get_revision_ui_diff( $post, $compare_from, $compare_to ),
		);
	}
	wp_send_json_success( $return );
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2778,7 +2778,7 @@
 	if ( ! $post = get_post( (int) $_REQUEST['post_id'] ) )
 		wp_send_json_error();
 
-	if ( ! current_user_can( 'read_post', $post->ID ) )
+	if ( ! current_user_can( 'edit_post', $post->ID ) )
 		wp_send_json_error();
 
 	// Really just pre-loading the cache here.
```
