# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2267_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2267_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php if ( ! defined('OC_ADMIN')) exit('Direct access is not allowed.');
/*
 * Copyright 2014 Osclass
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

    osc_add_hook('admin_page_header','customPageHeader');
    function customPageHeader() { ?>
        <h1><?php echo osc_apply_filter('custom_appearance_title', __('Appearance')); ?></h1>
    <?php
    }

    function customPageTitle($string) {
        return sprintf(__('Appearance &raquo; %s'), $string);
    }
    osc_add_filter('admin_title', 'customPageTitle');

    osc_current_admin_theme_path( 'parts/header.php' ); ?>
<!-- theme files -->
<div class="theme-files">
    <?php
        if( file_exists(__get('file')) ) {
            require_once __get('file');
        }
    ?>
</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
+    $file = __get('file');
     osc_add_hook('admin_page_header','customPageHeader');
     function customPageHeader() { ?>
         <h1><?php echo osc_apply_filter('custom_appearance_title', __('Appearance')); ?></h1>
@@ -30,8 +30,8 @@
 <!-- theme files -->
 <div class="theme-files">
     <?php
-        if( file_exists(__get('file')) ) {
-            require_once __get('file');
+        if(strpos($file, '../')===false && file_exists($file)) {
+            require_once $file;
         }
     ?>
 </div>
```
