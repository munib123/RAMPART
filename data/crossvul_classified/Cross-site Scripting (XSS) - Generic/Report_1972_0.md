# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1972_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1972_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-30 of the vulnerable file.

<div class="pagination">
    <ul>
    <?php
        $this->Paginator->options(array(
                'update' => '#elements_div',
                'evalScripts' => true,
                'before' => '$(".progress").show()',
                'complete' => '$(".progress").hide()',
        ));
        
        echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
        echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
        echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
    ?>
    </ul>
</div>

<table class="table table-striped table-hover table-condensed">
    <tr>
        <th class="short"><?php echo $this->Paginator->sort('key', __('Key'));?></th>
        <th><?php echo $this->Paginator->sort('value');?></th>
    </tr>
<?php
    foreach ($list as $item):
?>
        <tr>
            <td class="short"><?= h($item['GalaxyElement']['key']); ?></td>
            <td class="short"><?php if ($item['GalaxyElement']['key'] === 'refs') {
                echo '<a href="' . h($item['GalaxyElement']['value']) . '" rel="noreferrer noopener">' . h($item['GalaxyElement']['value']) . '</a>';
            } else if ($item['GalaxyElement']['key'] === 'country') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,7 +7,7 @@
                 'before' => '$(".progress").show()',
                 'complete' => '$(".progress").hide()',
         ));
-        
+
         echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
         echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
         echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
@@ -25,7 +25,14 @@
 ?>
         <tr>
             <td class="short"><?= h($item['GalaxyElement']['key']); ?></td>
-            <td class="short"><?php if ($item['GalaxyElement']['key'] === 'refs') {
+            <td class="short">
+            <?php if (
+                $item['GalaxyElement']['key'] === 'refs' &&
+                (
+                    substr($item['GalaxyElement']['value'], 0, 8) === 'https://' ||
+                    substr($item['GalaxyElement']['value'], 0, 7) === 'http://'
+                )
+            ) {
                 echo '<a href="' . h($item['GalaxyElement']['value']) . '" rel="noreferrer noopener">' . h($item['GalaxyElement']['value']) . '</a>';
             } else if ($item['GalaxyElement']['key'] === 'country') {
                 echo $this->Icon->countryFlag($item['GalaxyElement']['value']) . ' ' . h($item['GalaxyElement']['value']);
@@ -35,7 +42,7 @@
             ?></td>
         </tr>
     <?php
-        endforeach; 
+        endforeach;
     ?>
 </table>
 <p>
```
