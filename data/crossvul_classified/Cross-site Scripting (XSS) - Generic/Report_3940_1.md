# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3940_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3940_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php namespace Backend\FormWidgets;

use BackendAuth;
use Markdown;
use Backend\Classes\FormWidgetBase;

/**
 * Code Editor
 * Renders a code editor field.
 *
 * @package october\backend
 * @author Alexey Bobkov, Samuel Georges
 */
class MarkdownEditor extends FormWidgetBase
{
    //
    // Configurable properties
    //

    /**
     * @var string Display mode: split, tab.
     */
    public $mode = 'tab';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,8 @@
 <?php namespace Backend\FormWidgets;
 
+use Html;
+use Markdown;
 use BackendAuth;
-use Markdown;
 use Backend\Classes\FormWidgetBase;
 
 /**
@@ -42,12 +43,12 @@
     //
 
     /**
-     * @inheritDoc
+     * {@inheritDoc}
      */
     protected $defaultAlias = 'markdown';
 
     /**
-     * @inheritDoc
+     * {@inheritDoc}
      */
     public function init()
     {
@@ -60,7 +61,7 @@
     }
 
     /**
-     * @inheritDoc
+     * {@inheritDoc}
      */
     public function render()
     {
@@ -84,7 +85,7 @@
     }
 
     /**
-     * @inheritDoc
+     * {@inheritDoc}
      */
     protected function loadAssets()
     {
@@ -93,6 +94,34 @@
         $this->addJs('/modules/backend/formwidgets/codeeditor/assets/js/build-min.js', 'core');
     }
 
+    /**
+     * Check to see if the generated HTML should be cleaned to remove any potential XSS
+     *
+     * @return boolean
+     */
+    protected function shouldCleanHtml()
+    {
+        $user = BackendAuth::getUser();
+        return !$user || !$user->hasAccess('backend.allow_unsafe_markdown');
+    }
+
+    /**
+     * {@inheritDoc}
+     */
+    public function getSaveValue($value)
+    {
+        if ($this->shouldCleanHtml()) {
+            $value = Html::clean($value);
+        }
+
+        return $value;
+    }
+
+    /**
+     * AJAX handler to render the markdown as HTML
+     *
+     * @return array ['preview' => $generatedHTML]
+     */
     public function onRefresh()
     {
         $value = post($this->getFieldName());
@@ -100,6 +129,10 @@
             ? Markdown::parseSafe($value)
             : Markdown::parse($value);
 
+        if ($this->shouldCleanHtml()) {
+            $previewHtml = Html::clean($previewHtml);
+        }
+
         return [
             'preview' => $previewHtml
         ];
```
