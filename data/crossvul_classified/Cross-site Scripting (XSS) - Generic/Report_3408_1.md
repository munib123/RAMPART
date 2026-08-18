# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3408_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3408_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.

 * Silent updates that are needed even if no user is logged in.
 */
require_once(ROOT_DIR.'/includes/core.update.silent.php');

/**
 * Call the database update file to see if any change is needed,
 * but only if logged in as a system user.
 */
$core_update_allowed = array(9,8,7);
if (in_session_or_cookies($core_update_allowed)) {
	require_once(ROOT_DIR.'/includes/core.update.php');
}
?>
<!doctype html>
<html lang="<?php echo SITE_LANG; ?>">
<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">

	<title><?php echo html_output( $page_title . ' &raquo; ' . THIS_INSTALL_SET_TITLE ); ?></title>
	<?php meta_favicon(); ?>
	<script type="text/javascript" src="<?php echo BASE_URI; ?>includes/js/jquery.1.12.4.min.js"></script>

	<!--[if lt IE 9]>
		<script src="<?php echo BASE_URI; ?>includes/js/html5shiv.min.js"></script>
		<script src="<?php echo BASE_URI; ?>includes/js/respond.min.js"></script>
	<![endif]-->
	
	<?php
		require_once( 'assets.php' );

		load_css_files();
	?>
</head>

<body <?php echo add_body_class( $body_class ); ?>>
	<div class="container-custom">
		<header id="header" class="navbar navbar-static-top navbar-fixed-top">
			<ul class="nav pull-left nav_toggler">
				<li>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,7 @@
 	<meta http-equiv="X-UA-Compatible" content="IE=edge">
 	<meta name="viewport" content="width=device-width, initial-scale=1">
 
-	<title><?php echo html_output( $page_title . ' &raquo; ' . THIS_INSTALL_SET_TITLE ); ?></title>
+	<title><?php echo html_output( $page_title . ' &raquo; ' . htmlspecialchars(THIS_INSTALL_SET_TITLE, ENT_QUOTES, 'UTF-8') ); ?></title>
 	<?php meta_favicon(); ?>
 	<script type="text/javascript" src="<?php echo BASE_URI; ?>includes/js/jquery.1.12.4.min.js"></script>
 
@@ -84,7 +84,7 @@
 			</ul>
 
 			<div class="navbar-header">
-				<span class="navbar-brand"><a href="<?php echo SYSTEM_URI; ?>" target="_blank"><?php include('img/ps-icon.svg'); ?></a> <?php echo THIS_INSTALL_SET_TITLE; ?></span>
+				<span class="navbar-brand"><a href="<?php echo SYSTEM_URI; ?>" target="_blank"><?php include('img/ps-icon.svg'); ?></a> <?php echo html_output(THIS_INSTALL_SET_TITLE); ?></span>
 			</div>
 
 			<ul class="nav pull-right nav_account">
```
