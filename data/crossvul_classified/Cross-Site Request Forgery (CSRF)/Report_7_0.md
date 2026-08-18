# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 7_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `7_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 216-256 of the vulnerable file.

        if ($model === null) {
            throw new CHttpException(404, 'The requested page does not exist.');
        }

        return $model;
    }


    public function importManifest($templatename)
    {
        if (Permission::model()->hasGlobalPermission('templates', 'update')) {
            TemplateManifest::importManifest($templatename);
            $this->getController()->redirect(array("admin/themeoptions"));
        } else {
            Yii::app()->setFlashMessage(gT("We are sorry but you don't have permissions to do this."), 'error');
            $this->getController()->redirect(array("admin/themeoptions"));
        }

    }

    public function uninstall($templatename)
    {
        if (Permission::model()->hasGlobalPermission('templates', 'update')) {
            if (!Template::hasInheritance($templatename)) {
                TemplateConfiguration::uninstall($templatename);
            } else {
                Yii::app()->setFlashMessage(sprintf(gT("You can't uninstall template '%s' because some templates inherit from it."), $templatename), 'error');
            }
        } else {
            Yii::app()->setFlashMessage(gT("We are sorry but you don't have permissions to do this."), 'error');
        }

        $this->getController()->redirect(array("admin/themeoptions"));
    }

    /**
     * Performs the AJAX validation.
     * @param TemplateOptions $model the model to be validated
     */
    protected function performAjaxValidation($model)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -233,8 +233,9 @@
 
     }
 
-    public function uninstall($templatename)
-    {
+    public function uninstall()
+    {
+        $templatename = Yii::app()->request->getPost('templatename');
         if (Permission::model()->hasGlobalPermission('templates', 'update')) {
             if (!Template::hasInheritance($templatename)) {
                 TemplateConfiguration::uninstall($templatename);
@@ -262,12 +263,12 @@
 
     public function getPreviewTag()
     {
-        $templatename = Yii::app()->request->getPost('templatename');        
+        $templatename = Yii::app()->request->getPost('templatename');
         $oTemplate = TemplateConfiguration::getInstanceFromTemplateName($templatename);
         $previewTag = $oTemplate->getPreview();
         return Yii::app()->getController()->renderPartial(
             '/admin/super/_renderJson',
-            ['data' => ['image' =>  $previewTag]], 
+            ['data' => ['image' =>  $previewTag]],
             false,
             false
         );
```
