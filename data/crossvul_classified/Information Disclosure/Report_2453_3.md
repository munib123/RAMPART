# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2453_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2453_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<div class="feed form">
<?php echo $this->Form->create('Feed');?>
    <fieldset>
        <legend><?php echo __('Add MISP Feed');?></legend>
        <p><?php echo __('Add a new MISP feed source.');?></p>
    <?php
        echo $this->Form->input('enabled', array());
        echo $this->Form->input('caching_enabled', array('label' => __('Caching enabled')));
    ?>
        <div class="input clear"></div>
    <?php
        echo $this->Form->input('lookup_visible', array('label' => __('Lookup visible')));
        echo $this->Form->input('name', array(
                'div' => 'input clear',
                'placeholder' => __('Feed name'),
                'class' => 'form-control span6',
        ));
        echo $this->Form->input('provider', array(
                'div' => 'input clear',
                'label' => __('Provider'),
                'placeholder' => __('Name of the content provider'),
                'class' => 'form-control span6'
        ));
        echo $this->Form->input('input_source', array(
                'label' => __('Input Source'),
                'div' => 'input clear',
                'options' => array('network' => 'Network', 'local' => 'Local'),
                'class' => 'form-control span6'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,10 +2,16 @@
 <?php echo $this->Form->create('Feed');?>
     <fieldset>
         <legend><?php echo __('Add MISP Feed');?></legend>
-        <p><?php echo __('Add a new MISP feed source.');?></p>
-    <?php
-        echo $this->Form->input('enabled', array());
-        echo $this->Form->input('caching_enabled', array('label' => __('Caching enabled')));
+        <?php
+            if (!empty(Configure::read('Security.disable_local_feed_access'))) {
+                echo sprintf(
+                    '<p class="red bold">%s</p>',
+                    __('Warning: local feeds are currently disabled by policy, to re-enable the feature, set the Security.allow_local_feed_access flag in the server settings. This setting can only be set via the CLI.')
+                );
+            }
+            echo '<p>' . __('Add a new MISP feed source.') . '</p>';
+            echo $this->Form->input('enabled', array());
+            echo $this->Form->input('caching_enabled', array('label' => __('Caching enabled')));
     ?>
         <div class="input clear"></div>
     <?php
@@ -21,10 +27,14 @@
                 'placeholder' => __('Name of the content provider'),
                 'class' => 'form-control span6'
         ));
+        $options = array('network' => 'Network');
+        if (empty(Configure::read('Security.disable_local_feed_access'))) {
+            $options['local'] = 'Local';
+        }
         echo $this->Form->input('input_source', array(
                 'label' => __('Input Source'),
                 'div' => 'input clear',
-                'options' => array('network' => 'Network', 'local' => 'Local'),
+                'options' => $options,
                 'class' => 'form-control span6'
         ));
         ?>
```
