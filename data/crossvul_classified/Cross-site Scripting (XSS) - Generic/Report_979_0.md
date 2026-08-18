# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 979_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `979_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<script type='text/javascript'>
    var duplicatelabelcode='<?php eT('Error: You are trying to use duplicate label codes.','js'); ?>';
    var otherisreserved='<?php eT("Error: 'other' is a reserved keyword.",'js'); ?>';
</script>

<!-- quick add popup -->
<?php $this->renderPartial("./labels/_labelviewquickadd_view", array()); ?>

<div class="col-sm-12 labels">
    <div class="pagetitle h3">
        <?php eT("Labels") ?>
        <?php if(isset($model->label_name)): ?> 
            - <?=$model->label_name;?>
        <?php endif; ?>
    </div>
    <div class="container">
        <div class="row">

            <!-- Left content -->
            <div class="col-sm-12 content-right text-center">

                <!-- tabs -->
                <ul class="nav nav-tabs">
                    <?php  foreach ($lslanguages as $i => $language): ?>
                        <li role="presentation" <?php if($i==0){ echo 'class="active"';}?>>
                            <a data-toggle="tab" href='#neweditlblset<?php echo $i; ?>' >
                                <?php echo getLanguageNameFromCode($language, false); ?>
                            </a>
                        </li>
                    <?php endforeach;?>
                </ul>

                <!-- FORM -->
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
     <div class="pagetitle h3">
         <?php eT("Labels") ?>
         <?php if(isset($model->label_name)): ?> 
-            - <?=$model->label_name;?>
+            - <?php echo CHtml::encode($model->label_name); ?>
         <?php endif; ?>
     </div>
     <div class="container">
```
