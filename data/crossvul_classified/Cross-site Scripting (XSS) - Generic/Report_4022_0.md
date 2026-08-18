# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4022_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4022_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 82-122 of the vulnerable file.

                            'value' => $item['value'],
                            'style' => 'padding:0px;height:20px;margin-bottom:0px;width:90%;min-width:400px;',
                            'div' => false
                    ));
                ?>
                <input type="hidden" id="<?php echo 'Attribute' . $k . 'Save'; ?>" value=1 >
            </td>
            <td class="shortish">
                <?php
                    foreach ($item['related'] as $relation):
                        $popover = array(
                            'Event ID' => $relation['Event']['id'],
                            'Event Info' => $relation['Event']['info'],
                            'Category' => $relation['Attribute']['category'],
                            'Type' => $relation['Attribute']['type'],
                            'Value' => $relation['Attribute']['value'],
                            'Comment' => $relation['Attribute']['comment'],
                        );
                        $popoverHTML = '';
                        foreach ($popover as $key => $popoverElement) {
                            $popoverHTML .= '<span class=\'bold\'>' . $key . '</span>: <span class=\'blue bold\'>' . $popoverElement . '</span><br />';
                        }
                ?>
                        <a href="<?php echo $baseurl; ?>/events/view/<?php echo h($relation['Event']['id']);?>" data-toggle="popover" title="Attribute details" data-content="<?php echo h($popoverHTML); ?>" data-trigger="hover"><?php echo h($relation['Event']['id']);?></a>
                <?php
                    endforeach;
                    $correlationPopover = array('<span>', );
                ?>
            </td>
            <td class="short">
                <?php
                    if (!isset($item['categories'])) {
                        if (isset($defaultCategories[$item['default_type']])) {
                            $default = array_search($defaultCategories[$item['default_type']], $typeCategoryMapping[$item['default_type']]);
                        } else {
                            reset($typeCategoryMapping[$item['default_type']]);
                            $default = key($typeCategoryMapping[$item['default_type']]);
                        }
                    } else {
                        if (isset($item['category_default'])) $default = $item['category_default'];
                        else $default = array_search($item['categories'][0], $typeCategoryMapping[$item['default_type']]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,7 @@
                         );
                         $popoverHTML = '';
                         foreach ($popover as $key => $popoverElement) {
-                            $popoverHTML .= '<span class=\'bold\'>' . $key . '</span>: <span class=\'blue bold\'>' . $popoverElement . '</span><br />';
+                            $popoverHTML .= '<span class=\'bold\'>' . $key . '</span>: <span class=\'blue bold\'>' . h($popoverElement) . '</span><br />';
                         }
                 ?>
                         <a href="<?php echo $baseurl; ?>/events/view/<?php echo h($relation['Event']['id']);?>" data-toggle="popover" title="Attribute details" data-content="<?php echo h($popoverHTML); ?>" data-trigger="hover"><?php echo h($relation['Event']['id']);?></a>
```
