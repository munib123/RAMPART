# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 2352_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2352_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 18-59 of the vulnerable file.

	 * @package MantisBT
	 * @copyright Copyright (C) 2000 - 2002  Kenzaburo Ito - kenito@300baud.org
	 * @copyright Copyright (C) 2002 - 2014  MantisBT Team - mantisbt-dev@lists.sourceforge.net
	 * @link http://www.mantisbt.org
	 */
	 /**
	  * MantisBT Core API's
	  */
	require_once( 'core.php' );

	# Check for invalid access to signup page
	if ( OFF == config_get_global( 'allow_signup' ) || LDAP == config_get_global( 'login_method' ) ) {
		print_header_redirect( 'login_page.php' );
	}

	# signup page shouldn't be indexed by search engines
	html_robots_noindex();

	html_page_top1();
	html_page_top2a();

	$t_key = mt_rand( 0,99999 );
?>

<br />
<div align="center">
<form name="signup_form" method="post" action="signup.php">
<?php echo form_security_field( 'signup' ); ?>
<table class="width50" cellspacing="1">
<tr>
	<td class="form-title" colspan="3">
		<?php echo lang_get( 'signup_title' ) ?>
	</td>
</tr>
<tr class="row-1">
	<td class="category" width="30%">
		<?php echo lang_get( 'username' ) ?>:
	</td>
	<td width="70%" colspan="2">
		<input type="text" name="username" size="32" maxlength="<?php echo DB_FIELD_SIZE_USERNAME;?>" />
	</td>
</tr>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,8 +35,6 @@
 
 	html_page_top1();
 	html_page_top2a();
-
-	$t_key = mt_rand( 0,99999 );
 ?>
 
 <br />
@@ -68,6 +66,8 @@
 <?php
 	$t_allow_passwd = helper_call_custom_function( 'auth_can_change_password', array() );
 	if( ON == config_get( 'signup_use_captcha' ) && get_gd_version() > 0 && ( true == $t_allow_passwd ) ) {
+		session_set( CAPTCHA_KEY, mt_rand( 0,99999 ) );
+
 		# captcha image requires GD library and related option to ON
 ?>
 <tr class="row-1">
@@ -78,8 +78,7 @@
 		<?php print_captcha_input( 'captcha', '' ) ?>
 	</td>
 	<td>
-		<img src="make_captcha_img.php?public_key=<?php echo $t_key ?>" alt="visual captcha" />
-		<input type="hidden" name="public_key" value="<?php echo $t_key ?>" />
+		<img src="make_captcha_img.php" alt="visual captcha" />
 	</td>
 </tr>
 <?php
```
