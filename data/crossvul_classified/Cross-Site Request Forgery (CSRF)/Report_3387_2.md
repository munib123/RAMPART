# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3387_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3387_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-17 of the vulnerable file.

<div class="container">
	<section>
		<div class="alert">
			<span></span>
			<h3>LOCKED</h3>
		</div>
		<p>
			<strong><?=$locked_by["name"]?></strong> currently has this page locked for editing.  It was last accessed by <strong><?=$locked_by["name"]?></strong> on <strong><?=date("F j, Y @ g:ia",strtotime($last_accessed))?></strong>.<br />
		If you would like to edit this page anyway, please click "Unlock" below.  Otherwise, click "Cancel".
		</p>
	</section>
	<footer>
		<a href="javascript:history.go(-1);" class="button white">Cancel</a>
		&nbsp;
		<a href="?force=true" class="button blue">Unlock</a>
	</footer>
</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,6 @@
 	<footer>
 		<a href="javascript:history.go(-1);" class="button white">Cancel</a>
 		&nbsp;
-		<a href="?force=true" class="button blue">Unlock</a>
+		<a href="?force=true<? $admin->drawCSRFTokenGET() ?>" class="button blue">Unlock</a>
 	</footer>
 </div>
```
