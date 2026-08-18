# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5536_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5536_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-14 of the vulnerable file.

<form action="<?php echo 'resetpassword.php?'.$_SERVER['QUERY_STRING']; ?>" method="post">
	<fieldset>
		<?php if($_['success']): ?>
			<h1><?php echo $l->t('Your password was reset'); ?></h1>
			<p><a href="<?php echo OC::$WEBROOT ?>/"><?php echo $l->t('To login page'); ?></a></p>
		<?php else: ?>
			<p class="infield">
				<label for="password" class="infield"><?php echo $l->t( 'New password' ); ?></label>
				<input type="password" name="password" id="password" value="" required />
			</p>
			<input type="submit" id="submit" value="<?php echo $l->t('Reset password'); ?>" />
		<?php endif; ?>
	</fieldset>
</form>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-<form action="<?php echo 'resetpassword.php?'.$_SERVER['QUERY_STRING']; ?>" method="post">
+<form action="<?php echo 'resetpassword.php?user='.htmlentities($_GET['user']).'&token='.htmlentities($_GET['token']); ?>" method="post">
 	<fieldset>
 		<?php if($_['success']): ?>
 			<h1><?php echo $l->t('Your password was reset'); ?></h1>
```
