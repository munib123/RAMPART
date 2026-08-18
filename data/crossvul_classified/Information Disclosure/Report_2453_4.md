# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2453_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2453_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<div class="feed form">
<?php echo $this->Form->create('Feed');?>
    <fieldset>
        <legend><?php echo __('Edit MISP Feed');?></legend>
        <p><?php echo __('Edit a new MISP feed source.');?></p>
    <?php
            echo $this->Form->input('enabled', array(
                'type' => 'checkbox'
            ));
            echo $this->Form->input('caching_enabled', array(
                'type' => 'checkbox'
            ));
    ?>
        <div class="input clear"></div>
    <?php
            echo $this->Form->input('lookup_visible', array(
                'type' => 'checkbox'
            ));
            echo $this->Form->input('name', array(
                    'div' => 'input clear',
                    'placeholder' => __('Feed name'),
                    'class' => 'form-control span6',
            ));
            echo $this->Form->input('provider', array(
                    'div' => 'input clear',
                    'placeholder' => __('Name of the content provider'),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,8 +2,14 @@
 <?php echo $this->Form->create('Feed');?>
     <fieldset>
         <legend><?php echo __('Edit MISP Feed');?></legend>
-        <p><?php echo __('Edit a new MISP feed source.');?></p>
-    <?php
+        <?php
+            if (!empty(Configure::read('Security.disable_local_feed_access'))) {
+                echo sprintf(
+                    '<p class="red bold">%s</p>',
+                    __('Warning: local feeds are currently disabled by policy, to re-enable the feature, set the Security.allow_local_feed_access flag in the server settings. This setting can only be set via the CLI.')
+                );
+            }
+            echo '<p>' . __('Edit a new MISP feed source.') . '</p>';
             echo $this->Form->input('enabled', array(
                 'type' => 'checkbox'
             ));
@@ -26,9 +32,13 @@
                     'placeholder' => __('Name of the content provider'),
                     'class' => 'form-control span6'
             ));
+            $options = array('network' => 'Network');
+            if (empty(Configure::read('Security.disable_local_feed_access'))) {
+                $options['local'] = 'Local';
+            }
             echo $this->Form->input('input_source', array(
                     'div' => 'input clear',
-                    'options' => array('network' => 'Network', 'local' => 'Local'),
+                    'options' => $options,
                     'class' => 'form-control span6'
             ));
             ?>
```
