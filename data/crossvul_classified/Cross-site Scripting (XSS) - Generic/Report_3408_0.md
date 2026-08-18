# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3408_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3408_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 15-56 of the vulnerable file.

		define( 'BASE_URI', '../' );
	}

	$lang = ( defined('SITE_LANG') ) ? SITE_LANG : 'en';

	$header_vars = array(
						'html_lang'		=> $lang,
						'title'			=> $page_title_install . ' &raquo; ' . SYSTEM_NAME,
						'header_title'	=> SYSTEM_NAME . ' ' . __('setup','cftp_admin'),
					);
}

else {
	/**
	 * Check if the ProjectSend is installed. Done only on the log in form
	 * page since all other are inaccessible if no valid session or cookie
	 * is set.
	 */
	$header_vars = array(
						'html_lang'		=> SITE_LANG,
						'title'			=> $page_title . ' &raquo; ' . THIS_INSTALL_SET_TITLE,
						'header_title'	=> THIS_INSTALL_SET_TITLE,
					);

	if ( !is_projectsend_installed() ) {
		header("Location:install/index.php");
		exit;
	}
	
	$load_scripts = array(
						'social_login',
						'recaptcha',
						'chosen',
					);
	
	/**
	 * This is defined on the public download page.
	 * So even logged in users can access it.
	 */
	if (!isset($dont_redirect_if_logged)) {
		/** If logged as a system user, go directly to the back-end homepage */
		if (in_session_or_cookies($allowed_levels)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,8 +32,8 @@
 	 */
 	$header_vars = array(
 						'html_lang'		=> SITE_LANG,
-						'title'			=> $page_title . ' &raquo; ' . THIS_INSTALL_SET_TITLE,
-						'header_title'	=> THIS_INSTALL_SET_TITLE,
+						'title'			=> $page_title . ' &raquo; ' . html_output(THIS_INSTALL_SET_TITLE),
+						'header_title'	=> html_output(THIS_INSTALL_SET_TITLE),
 					);
 
 	if ( !is_projectsend_installed() ) {
```
