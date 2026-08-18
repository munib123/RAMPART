# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3941_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3941_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 3-43 of the vulnerable file.

use Lang;
use Input;
use Response;
use Validator;
use RainLab\Blog\Models\Post as PostModel;
use Backend\Classes\FormWidgetBase;
use Backend\FormWidgets\MarkdownEditor;
use System\Models\File;
use ValidationException;
use SystemException;
use Exception;

/**
 * Special markdown editor for the Create/Edit Post form.
 *
 * @package rainlab\blog
 * @author Alexey Bobkov, Samuel Georges
 */
class BlogMarkdown extends MarkdownEditor
{
    public function init()
    {
        $this->viewPath = base_path().'/modules/backend/formwidgets/markdowneditor/partials';

        $this->checkUploadPostback();

        parent::init();
    }

    protected function loadAssets()
    {
        $this->assetPath = '/modules/backend/formwidgets/markdowneditor/assets';
        parent::loadAssets();
    }

    public function onRefresh()
    {
        $content = post($this->formField->getName());

        $previewHtml = PostModel::formatHtml($content, true);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,9 @@
  */
 class BlogMarkdown extends MarkdownEditor
 {
+    /**
+     * {@inheritDoc}
+     */
     public function init()
     {
         $this->viewPath = base_path().'/modules/backend/formwidgets/markdowneditor/partials';
@@ -29,12 +32,28 @@
         parent::init();
     }
 
+    /**
+     * {@inheritDoc}
+     */
     protected function loadAssets()
     {
         $this->assetPath = '/modules/backend/formwidgets/markdowneditor/assets';
         parent::loadAssets();
     }
 
+    /**
+     * Disable HTML cleaning on the widget level since the PostModel will handle it
+     *
+     * @return boolean
+     */
+    protected function shouldCleanHtml()
+    {
+        return false;
+    }
+
+    /**
+     * {@inheritDoc}
+     */
     public function onRefresh()
     {
         $content = post($this->formField->getName());
@@ -46,6 +65,11 @@
         ];
     }
 
+    /**
+     * Handle images being uploaded to the blog post
+     *
+     * @return void
+     */
     protected function checkUploadPostback()
     {
         if (!post('X_BLOG_IMAGE_UPLOAD')) {
@@ -90,11 +114,9 @@
             ];
 
             $response = Response::make()->setContent($result);
-            $response->send();
+            $this->controller->setResponse($response);
 
-            die();
-        }
-        catch (Exception $ex) {
+        } catch (Exception $ex) {
             $message = $uploadedFileName
                 ? Lang::get('cms::lang.asset.error_uploading_file', ['name' => $uploadedFileName, 'error' => $ex->getMessage()])
                 : $ex->getMessage();
@@ -105,9 +127,7 @@
             ];
 
             $response = Response::make()->setContent($result);
-            $response->send();
-
-            die();
+            $this->controller->setResponse($response);
         }
     }
 }
```
