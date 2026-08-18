# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4305_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4305_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-16 of the vulnerable file.

<?php
/* @var $this AdminController */
/* @var Quota $oQuota */
/* @var Question $oQuestion */
?>

<div class='row'>
    <h2><?php echo sprintf(gT("New answer for quota '%s'"), $oQuota->name);?></h2>
    <p class="lead"><?php eT("Set equation value");?></p>
    <div class='form-group'>
        <div class='col-sm-5 col-sm-offset-4'>
            <input type="text" class='form-control' name="quota_anscode" />
        </div>
    </div>
</div>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
 ?>
 
 <div class='row'>
-    <h2><?php echo sprintf(gT("New answer for quota '%s'"), $oQuota->name);?></h2>
+    <h2><?php echo sprintf(gT("New answer for quota '%s'"), htmlentities($oQuota->name));?></h2>
     <p class="lead"><?php eT("Set equation value");?></p>
     <div class='form-group'>
         <div class='col-sm-5 col-sm-offset-4'>
```
