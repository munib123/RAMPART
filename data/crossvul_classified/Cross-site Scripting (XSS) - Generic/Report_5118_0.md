# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5118_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5118_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 630-670 of the vulnerable file.


	if( !is_blank( $t_page ) && file_exists( $t_page ) && !is_dir( $t_page ) ) {
		include( $t_page );
	}
}

/**
 * A function that outputs that an operation was successful and provides a redirect link.
 * @param string $p_redirect_url The url to redirect to.
 * @param string $p_message      Message to display to the user.
 * @return void
 */
function html_operation_successful( $p_redirect_url, $p_message = '' ) {
	echo '<div class="success-msg">';

	if( !is_blank( $p_message ) ) {
		echo $p_message . '<br />';
	}

	echo lang_get( 'operation_successful' ).'<br />';
	print_bracket_link( $p_redirect_url, lang_get( 'proceed' ) );
	echo '</div>';
}

/**
 * Checks if the current page load was triggered by auto-refresh or real activity
 * @return bool true: auto-refresh, false: triggered by user.
 */
function html_is_auto_refresh() {
	return gpc_get_bool( 'refresh' );
}

/**
 * (13) Print the page footer information
 * @return void
 */
function html_footer() {
	global $g_queries_array, $g_request_time;

	# If a user is logged in, update their last visit time.
	# We do this at the end of the page so that:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -647,7 +647,7 @@
 	}
 
 	echo lang_get( 'operation_successful' ).'<br />';
-	print_bracket_link( $p_redirect_url, lang_get( 'proceed' ) );
+	print_bracket_link( string_sanitize_url( $p_redirect_url ), lang_get( 'proceed' ) );
 	echo '</div>';
 }
 
```
