# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3246_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3246_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-6 of the vulnerable file.

<div>
<h3>Landing page for <?php echo $org;?></h3>
<div>
<?php echo h($landingPage);?>
</div>
</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 <div>
-<h3>Landing page for <?php echo $org;?></h3>
+<h3>Landing page for <?php echo h($org);?></h3>
 <div>
 <?php echo h($landingPage);?>
 </div>
```
