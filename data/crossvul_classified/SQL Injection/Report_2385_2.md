# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2385_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2385_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<div class="panel panel-default">
    <div class="panel-heading"><?php echo Yii::t('AdminModule.views_logging_index', '<strong>Error</strong> logging'); ?></div>
    <div class="panel-body">

        <div>
            <?php echo Yii::t('AdminModule.views_logging_index', 'Total {count} entries found.', array("{count}" => $itemCount)); ?>
            <span
                class="pull-right"><?php echo Yii::t('AdminModule.views_logging_index', 'Displaying {count} entries per page.', array("{count}" => $pageSize)); ?></span>
        </div>

        <hr>

        <ul class="media-list">
            <?php foreach ($entries as $entry) : ?>

                <li class="media">
                    <div class="media-body">

                        <?php
                        $labelClass = "label-primary";
                        if ($entry->level == 'error') {
                            $labelClass = "label-danger";
                        } elseif ($entry->level == 'error') {
                            $labelClass = "label-warning";
                        } elseif ($entry->level == 'info') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,13 +2,16 @@
     <div class="panel-heading"><?php echo Yii::t('AdminModule.views_logging_index', '<strong>Error</strong> logging'); ?></div>
     <div class="panel-body">
 
+        
         <div>
             <?php echo Yii::t('AdminModule.views_logging_index', 'Total {count} entries found.', array("{count}" => $itemCount)); ?>
-            <span
-                class="pull-right"><?php echo Yii::t('AdminModule.views_logging_index', 'Displaying {count} entries per page.', array("{count}" => $pageSize)); ?></span>
+            
+            <span class="pull-right"><?php echo Yii::t('AdminModule.views_logging_index', 'Displaying {count} entries per page.', array("{count}" => $pageSize)); ?></span>
         </div>
 
         <hr>
+        
+        
 
         <ul class="media-list">
             <?php foreach ($entries as $entry) : ?>
@@ -28,17 +31,21 @@
                         ?>
 
                         <h4 class="media-heading">
-                            <span class="label <?php echo $labelClass; ?>"><?php echo $entry->level; ?></span>&nbsp;
+                            <span class="label <?php echo $labelClass; ?>"><?php echo CHtml::encode($entry->level); ?></span>&nbsp;
                             <?php echo date('r', $entry->logtime); ?>&nbsp;
-                            <span class="pull-right"><?php echo $entry->category; ?></span>
+                            <span class="pull-right"><?php echo CHtml::encode($entry->category); ?></span>
                         </h4>
-                        <?php echo $entry->message; ?>
+                        <?php echo CHtml::encode($entry->message); ?>
                     </div>
                 </li>
 
             <?php endforeach; ?>
         </ul>
 
+        <?php if ($itemCount != 0): ?>
+            <div class="pull-right"><?php echo HHtml::postLink('Flush entries', array('flush'), array('class'=>'btn btn-danger')); ?></div>
+        <?php endif; ?>
+    
 
         <center>
             <?php
```
