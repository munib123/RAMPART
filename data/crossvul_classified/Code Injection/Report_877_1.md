# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 877_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `877_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<!-- Use .flex-column to set a vertical direction -->
<ul class="nav flex-column pt-4">

	<li class="nav-item mb-4" style="margin-left: -4px;">
		<img src="<?php echo HTML_PATH_ADMIN_THEME ?>img/logo.svg" width="20" height="20" alt="bludit-logo"><span class="ml-2 align-middle"><?php echo (defined('BLUDIT_PRO'))?'BLUDIT PRO':'BLUDIT' ?></span>
	</li>

	<li class="nav-item">
		<a class="nav-link" href="<?php echo HTML_PATH_ADMIN_ROOT.'dashboard' ?>"><span class="oi oi-dashboard"></span><?php $L->p('Dashboard') ?></a>
	</li>
	<li class="nav-item">
		<a class="nav-link" target="_blank" href="<?php echo HTML_PATH_ROOT ?>"><span class="oi oi-external-link"></span><?php $L->p('Website') ?></a>
	</li>

	<li class="nav-item mt-3">
		<a class="nav-link" href="<?php echo HTML_PATH_ADMIN_ROOT.'new-content' ?>"><span style="color: #007bff;" class="oi oi-plus"></span><?php $L->p('New content') ?></a>
	</li>

	<?php if (checkRole(array('editor'),false)): ?>
	<li class="nav-item">
		<a class="nav-link" href="<?php echo HTML_PATH_ADMIN_ROOT.'content' ?>"><span class="oi oi-layers"></span><?php $L->p('Content') ?></a>
	</li>

	<li class="nav-item">
		<a class="nav-link" href="<?php echo HTML_PATH_ADMIN_ROOT.'edit-user/'.$login->username() ?>"><span class="oi oi-person"></span><?php $L->p('Profile') ?></a>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 <ul class="nav flex-column pt-4">
 
 	<li class="nav-item mb-4" style="margin-left: -4px;">
-		<img src="<?php echo HTML_PATH_ADMIN_THEME ?>img/logo.svg" width="20" height="20" alt="bludit-logo"><span class="ml-2 align-middle"><?php echo (defined('BLUDIT_PRO'))?'BLUDIT PRO':'BLUDIT' ?></span>
+		<img src="<?php echo HTML_PATH_CORE_IMG ?>logo.svg" width="20" height="20" alt="bludit-logo"><span class="ml-2 align-middle"><?php echo (defined('BLUDIT_PRO'))?'BLUDIT PRO':'BLUDIT' ?></span>
 	</li>
 
 	<li class="nav-item">
```
