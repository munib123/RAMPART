# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 877_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `877_2`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<!DOCTYPE html>
<html>
<head>
	<title><?php echo $layout['title'] ?></title>
	<meta charset="<?php echo CHARSET ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<meta name="robots" content="noindex,nofollow">
	<meta name="generator" content="Bludit">

	<!-- Favicon -->
	<link rel="shortcut icon" type="image/x-icon" href="<?php echo DOMAIN_ADMIN_THEME.'img/favicon.png?version='.BLUDIT_VERSION ?>">

	<!-- CSS -->
	<?php
		echo Theme::cssBootstrap();
		echo Theme::css(array(
			'jquery-auto-complete.css',
			'open-iconic-bootstrap.min.css',
			'jquery.datetimepicker.min.css',
			'bludit.css'
		), DOMAIN_ADMIN_THEME_CSS);
	?>

	<!-- Javascript -->
	<?php
		echo Theme::jquery();
		echo Theme::jsBootstrap();
		echo Theme::js(array(
			'jquery-auto-complete.min.js',
			'jquery.datetimepicker.full.min.js'
		), DOMAIN_ADMIN_THEME_JS);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
 	<meta name="generator" content="Bludit">
 
 	<!-- Favicon -->
-	<link rel="shortcut icon" type="image/x-icon" href="<?php echo DOMAIN_ADMIN_THEME.'img/favicon.png?version='.BLUDIT_VERSION ?>">
+	<link rel="shortcut icon" type="image/x-icon" href="<?php echo HTML_PATH_CORE_IMG.'favicon.png?version='.BLUDIT_VERSION ?>">
 
 	<!-- CSS -->
 	<?php
```
