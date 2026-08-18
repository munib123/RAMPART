# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 877_13
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `877_13`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 566-606 of the vulnerable file.

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	if (Text::length($_POST['password'])<6) {
		$errorText = $L->g('password-must-be-at-least-6-characters-long');
		error_log('[ERROR] '.$errorText, 0);
	} else {
		install($_POST['password'], $_POST['timezone']);
		redirect(HTML_PATH_ROOT);
	}
}

?>
<!DOCTYPE html>
<html>
<head>
	<title><?php echo $L->get('Bludit Installer') ?></title>
	<meta charset="<?php echo CHARSET ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<meta name="robots" content="noindex,nofollow">

	<!-- Favicon -->
	<link rel="shortcut icon" type="image/x-icon" href="bl-kernel/admin/themes/booty/img/favicon.png?version=<?php echo time() ?>">

	<!-- CSS -->
	<link rel="stylesheet" type="text/css" href="bl-kernel/css/bootstrap.min.css?version=<?php echo time() ?>">
	<link rel="stylesheet" type="text/css" href="bl-kernel/admin/themes/booty/css/bludit.css?version=<?php echo time() ?>">

	<!-- Javascript -->
	<script charset="utf-8" src="bl-kernel/js/jquery.min.js?version=<?php echo time() ?>"></script>
	<script charset="utf-8" src="bl-kernel/js/bootstrap.bundle.min.js?version=<?php echo time() ?>"></script>
	<script charset="utf-8" src="bl-kernel/js/jstz.min.js?version=<?php echo time() ?>"></script>
</head>
<body class="login">
<div class="container">
	<div class="row justify-content-md-center pt-5">
		<div class="col-md-4 pt-5">
			<h1 class="text-center mb-5 mt-5 font-weight-normal text-uppercase" style="color: #555;"><?php echo $L->get('Bludit Installer') ?></h1>
			<?php
			$system = checkSystem();
			if (!empty($system)) {
				foreach ($system as $error) {
					echo '
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -583,7 +583,7 @@
 	<meta name="robots" content="noindex,nofollow">
 
 	<!-- Favicon -->
-	<link rel="shortcut icon" type="image/x-icon" href="bl-kernel/admin/themes/booty/img/favicon.png?version=<?php echo time() ?>">
+	<link rel="shortcut icon" type="image/x-icon" href="bl-kernel/img/favicon.png?version=<?php echo time() ?>">
 
 	<!-- CSS -->
 	<link rel="stylesheet" type="text/css" href="bl-kernel/css/bootstrap.min.css?version=<?php echo time() ?>">
```
