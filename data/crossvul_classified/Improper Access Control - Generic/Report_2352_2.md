# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 2352_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2352_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

# along with MantisBT.  If not, see <http://www.gnu.org/licenses/>.

	/**
	 * @package MantisBT
	 * @copyright Copyright (C) 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
	 * @copyright Copyright (C) 2002 - 2014  MantisBT Team - mantisbt-dev@lists.sourceforge.net
	 * @link http://www.mantisbt.org
	 */
	 /**
	  * MantisBT Core API's
	  */
	require_once( 'core.php' );

	require_once( 'email_api.php' );

	form_security_validate( 'signup' );

	$f_username		= strip_tags( gpc_get_string( 'username' ) );
	$f_email		= strip_tags( gpc_get_string( 'email' ) );
	$f_captcha		= gpc_get_string( 'captcha', '' );
	$f_public_key	= gpc_get_int( 'public_key', '' );

	$f_username = trim( $f_username );
	$f_email = email_append_domain( trim( $f_email ) );
	$f_captcha = utf8_strtolower( trim( $f_captcha ) );

	# force logout on the current user if already authenticated
	if( auth_is_user_authenticated() ) {
		auth_logout();
	}

	# Check to see if signup is allowed
	if ( OFF == config_get_global( 'allow_signup' ) ) {
		print_header_redirect( 'login_page.php' );
		exit;
	}

	if( ON == config_get( 'signup_use_captcha' ) && get_gd_version() > 0 	&&
				helper_call_custom_function( 'auth_can_change_password', array() ) ) {
		# captcha image requires GD library and related option to ON
		$t_key = utf8_strtolower( utf8_substr( md5( config_get( 'password_confirm_hash_magic_string' ) . $f_public_key ), 1, 5) );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,6 @@
 	$f_username		= strip_tags( gpc_get_string( 'username' ) );
 	$f_email		= strip_tags( gpc_get_string( 'email' ) );
 	$f_captcha		= gpc_get_string( 'captcha', '' );
-	$f_public_key	= gpc_get_int( 'public_key', '' );
 
 	$f_username = trim( $f_username );
 	$f_email = email_append_domain( trim( $f_email ) );
@@ -51,8 +50,10 @@
 
 	if( ON == config_get( 'signup_use_captcha' ) && get_gd_version() > 0 	&&
 				helper_call_custom_function( 'auth_can_change_password', array() ) ) {
+		$t_form_key = session_get( CAPTCHA_KEY );
+
 		# captcha image requires GD library and related option to ON
-		$t_key = utf8_strtolower( utf8_substr( md5( config_get( 'password_confirm_hash_magic_string' ) . $f_public_key ), 1, 5) );
+		$t_key = utf8_strtolower( utf8_substr( md5( config_get( 'password_confirm_hash_magic_string' ) . $t_form_key ), 1, 5) );
 
 		if ( $t_key != $f_captcha ) {
 			trigger_error( ERROR_SIGNUP_NOT_MATCHING_CAPTCHA, ERROR );
```
