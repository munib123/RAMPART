# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 704_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `704_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 239-279 of the vulnerable file.

$personalDataContent = '<ul>';
$properties = json_decode($propertiesToJson);
$webCoursePath = api_get_path(WEB_COURSE_PATH);
$showWarningMessage = false;
foreach ($properties as $key => $value) {
    if (is_array($value) || is_object($value)) {
        switch ($key) {
            case 'classes':
                foreach ($value as $category => $subValue) {
                    $categoryName = 'Social group';
                    if ($category == 0) {
                        $categoryName = 'Class';
                    }
                    $personalDataContent .= '<li class="advanced_options" id="personal-data-list-'.$category.'">';
                    $personalDataContent .= '<u>'.$categoryName.'</u> &gt;</li>';
                    $personalDataContent .= '<ul id="personal-data-list-'.$category.'_options" style="display:none;">';
                    if (empty($subValue)) {
                        $personalDataContent .= '<li>'.get_lang('NoData').'</li>';
                    } else {
                        foreach ($subValue as $subSubValue) {
                            $personalDataContent .= '<li>'.$subSubValue.'</li>';
                        }
                    }
                    $personalDataContent .= '</ul>';
                }
                break;
            case 'extraFields':
                $personalDataContent .= '<li>'.$key.': </li><ul>';
                if (empty($value)) {
                    $personalDataContent .= '<li>'.get_lang('NoData').'</li>';
                } else {
                    foreach ($value as $subValue) {
                        $personalDataContent .= '<li>'.$subValue->variable.': '.$subValue->value.'</li>';
                    }
                }
                $personalDataContent .= '</ul>';
                break;
            case 'dropBoxSentFiles':
                foreach ($value as $category => $subValue) {
                    $personalDataContent .= '<li class="advanced_options" id="personal-data-list-'.$category.'">';
                    $personalDataContent .= '<u>'.get_lang($category).'</u> &gt;</li>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -256,7 +256,7 @@
                         $personalDataContent .= '<li>'.get_lang('NoData').'</li>';
                     } else {
                         foreach ($subValue as $subSubValue) {
-                            $personalDataContent .= '<li>'.$subSubValue.'</li>';
+                            $personalDataContent .= '<li>'.Security::remove_XSS($subSubValue).'</li>';
                         }
                     }
                     $personalDataContent .= '</ul>';
@@ -268,7 +268,7 @@
                     $personalDataContent .= '<li>'.get_lang('NoData').'</li>';
                 } else {
                     foreach ($value as $subValue) {
-                        $personalDataContent .= '<li>'.$subValue->variable.': '.$subValue->value.'</li>';
+                        $personalDataContent .= '<li>'.$subValue->variable.': '.Security::remove_XSS($subValue->value).'</li>';
                     }
                 }
                 $personalDataContent .= '</ul>';
@@ -292,7 +292,7 @@
                                 );
                                 $personalDataContent .= '<li>'.$documentLink.'</li>';
                             } else {
-                                $personalDataContent .= '<li>'.$subSubValue.'</li>';
+                                $personalDataContent .= '<li>'.Security::remove_XSS($subSubValue).'</li>';
                             }
                         }
                     }
@@ -312,7 +312,7 @@
                     $personalDataContent .= '<li>'.get_lang('NoData').'</li>';
                 } else {
                     foreach ($value as $subValue) {
-                        $personalDataContent .= '<li>'.$subValue.'</li>';
+                        $personalDataContent .= '<li>'.Security::remove_XSS($subValue).'</li>';
                     }
                 }
                 $personalDataContent .= '</ul>';
@@ -350,7 +350,7 @@
             $personalDataContent .= '<li>'.$key.': '.get_lang('ComplexDataNotShown').'</li>';
         }*/
     } else {
-        $personalDataContent .= '<li>'.$key.': '.$value.'</li>';
+        $personalDataContent .= '<li>'.$key.': '.Security::remove_XSS($value).'</li>';
     }
 }
 $personalDataContent .= '</ul>';
```
