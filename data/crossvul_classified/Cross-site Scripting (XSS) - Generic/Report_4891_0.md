# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4891_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4891_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1168-1208 of the vulnerable file.

	/**
	 * Produce the column values for the custom columns we created
	 */
	function action_manage_posts_custom_column( $column_name, $ticket_id ) {

		switch ( $column_name ) {
			case 'updated':
				$modified_gmt = get_post_modified_time( 'U', true, $ticket_id );
				echo sprintf( __( '%s ago', 'supportflow' ), human_time_diff( $modified_gmt ) );
				break;
			case 'sf_excerpt':
				$replies = SupportFlow()->get_ticket_replies( $ticket_id, array( 'posts_per_page' => 1, 'order' => 'ASC' ) );
				if ( ! isset( $replies[0] ) ) {
					echo '—';
					break;
				}
				$first_reply = $replies[0]->post_content;
				if ( strlen( $first_reply ) > 50 ) {
					$first_reply = substr( $first_reply, 0, 50 );
				}
				echo $first_reply;
				break;
			case 'customers':
				$customers = SupportFlow()->get_ticket_customers( $ticket_id, array( 'fields' => 'emails' ) );
				if ( empty( $customers ) ) {
					echo '—';
					break;
				}
				foreach ( $customers as $key => $customer_email ) {
					$args              = array(
						SupportFlow()->customers_tax => SupportFlow()->get_email_hash( $customer_email ),
						'post_type'                    => SupportFlow()->post_type,
					);
					$customer_photo  = get_avatar( $customer_email, 16 );
					$customer_link   = '<a class="customer_link" href="' . esc_url( add_query_arg( $args, admin_url( 'edit.php' ) ) ) . '">' . $customer_email . '</a>';
					$customers[$key] = $customer_photo . '&nbsp;' . $customer_link;
				}
				echo implode( '<br />', $customers );
				break;
			case 'status':
				$post_status = get_post_status( $ticket_id );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1185,7 +1185,7 @@
 				if ( strlen( $first_reply ) > 50 ) {
 					$first_reply = substr( $first_reply, 0, 50 );
 				}
-				echo $first_reply;
+				echo esc_html( $first_reply );
 				break;
 			case 'customers':
 				$customers = SupportFlow()->get_ticket_customers( $ticket_id, array( 'fields' => 'emails' ) );
```
