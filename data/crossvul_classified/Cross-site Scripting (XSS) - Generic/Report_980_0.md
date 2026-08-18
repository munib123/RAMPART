# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 980_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `980_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<div class="<?php echo $sizeClass; ?> ls-flex-column ls-panelboxes-panelbox text-primary" >
    <div class="panel panel-primary panel-clickable ls-panelboxes-panelbox-inner selector__<?=str_replace(' ', '_', strtolower($title))?>"
        id="panel-<?php echo $position; ?>"
        data-url="<?php echo $url; ?>"
        <?php if ($external): ?>
            data-target="_blank"
        <?php endif; ?>
    >
        <div class="panel-heading">
            <div class="panel-title h4"><?php eT($title); ?></div>
        </div>
        <div class="panel-body">
            <div class="panel-body-ico">
                <span class="sr-only"><?php eT($title); ?></span>
                <span class="<?php echo CHtml::encode($ico); ?>" style="font-size: 4em">
                </span>
            </div>
            <div class="panel-body-link">
                <?php eT($description); ?>
                <?php if ($external): ?>
                    &nbsp;<i class="fa fa-external-link"></i>
                <?php endif; ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 <div class="<?php echo $sizeClass; ?> ls-flex-column ls-panelboxes-panelbox text-primary" >
-    <div class="panel panel-primary panel-clickable ls-panelboxes-panelbox-inner selector__<?=str_replace(' ', '_', strtolower($title))?>"
+    <div class="panel panel-primary panel-clickable ls-panelboxes-panelbox-inner selector__<?php echo CHtml::encode(str_replace(' ', '_', strtolower(strip_tags($title)))) ?>"
         id="panel-<?php echo $position; ?>"
-        data-url="<?php echo $url; ?>"
+        data-url="<?php echo CHtml::encode($url); ?>"
         <?php if ($external): ?>
             data-target="_blank"
         <?php endif; ?>
```
