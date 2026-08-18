# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2792_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2792_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 443-483 of the vulnerable file.

	wp_update_user($user_data);
}


/**
 * Sanitize the nicename using sanitize_user
 * See discussion: http://wordpress.org/support/topic/377030
 * 
 * @since 1.4
 */
add_filter( 'shibboleth_user_nicename', 'sanitize_user' );

/**
 * Add a "Login with Shibboleth" link to the WordPress login form.  This link 
 * will be wrapped in a <p> with an id value of "shibboleth_login" so that 
 * deployers can style this however they choose.
 */
function shibboleth_login_form() {
	$login_url = add_query_arg('action', 'shibboleth');
	$login_url = remove_query_arg('reauth', $login_url);
	echo '<p id="shibboleth_login"><a href="' . $login_url . '">' . __('Login with Shibboleth', 'shibboleth') . '</a></p>';
}
add_action('login_form', 'shibboleth_login_form');


/**
 * Insert directives into .htaccess file to enable Shibboleth Lazy Sessions.
 */
function shibboleth_insert_htaccess() {
	if ( got_mod_rewrite() ) {
		$htaccess = get_home_path() . '.htaccess';
		$rules = array('AuthType shibboleth', 'Require shibboleth');
		insert_with_markers($htaccess, 'Shibboleth', $rules);
	}
}


/**
 * Remove directives from .htaccess file to enable Shibboleth Lazy Sessions.
 */
function shibboleth_remove_htaccess() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -460,7 +460,7 @@
 function shibboleth_login_form() {
 	$login_url = add_query_arg('action', 'shibboleth');
 	$login_url = remove_query_arg('reauth', $login_url);
-	echo '<p id="shibboleth_login"><a href="' . $login_url . '">' . __('Login with Shibboleth', 'shibboleth') . '</a></p>';
+	echo '<p id="shibboleth_login"><a href="' . esc_url($login_url) . '">' . __('Login with Shibboleth', 'shibboleth') . '</a></p>';
 }
 add_action('login_form', 'shibboleth_login_form');
 
```
