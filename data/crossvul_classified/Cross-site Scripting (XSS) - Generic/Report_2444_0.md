# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2444_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2444_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php
    echo $this->Html->script('d3');
    echo $this->Html->script('cal-heatmap');
    echo $this->Html->css('cal-heatmap');
?>
<div class = "index">
    <h2><?php echo __('Statistics');?></h2>
    <?php
        echo $this->element('Users/statisticsMenu');
        $types = array(
                'local' => array('selected' => false, 'text' => __('Local organisations')),
                'external' => array('selected' => false, 'text' => __('Known remote organisations')),
                'all' => array('selected' => false, 'text' => __('All organisations'))
        );
        $types[$scope]['selected'] = true;
    ?>
    <h4><?php echo __('Organisation list');?></h4>
    <p><?php echo __('Quick overview over the organisations residing on or known by this instance.');?></p>
    <div class="tabMenuFixedContainer" style="display:inline-block;">
            <?php
                foreach ($types as $key => $value):
            ?>
                <span class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer <?php if ($value['selected']) echo 'tabMenuActive'; ?>" onclick="window.location='/users/statistics/orgs/scope:<?php echo h($key);?>'"><?php echo h($value['text']); ?></span>
            <?php
                endforeach;
            ?>
    </div>
    <table class="table table-striped table-hover table-condensed" style="width:50%;">
    <tr>
            <th><?php echo __('Logo');?></th>
            <th><?php echo __('Name');?></th>
            <th><?php echo __('Users');?></th>
            <th><?php echo __('Events');?></th>
            <th><?php echo __('Attributes');?></th>
            <th><?php echo __('Nationality');?></th>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,9 @@
                 'external' => array('selected' => false, 'text' => __('Known remote organisations')),
                 'all' => array('selected' => false, 'text' => __('All organisations'))
         );
-        $types[$scope]['selected'] = true;
+        if (isset($types[$scope])) {
+            $types[$scope]['selected'] = true;
+        }
     ?>
     <h4><?php echo __('Organisation list');?></h4>
     <p><?php echo __('Quick overview over the organisations residing on or known by this instance.');?></p>
```
