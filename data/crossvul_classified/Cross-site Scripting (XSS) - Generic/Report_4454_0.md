# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4454_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4454_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php

App::uses('AppController', 'Controller');

class TemplateElementsController extends AppController
{
    public $components = array('Security' ,'RequestHandler');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                    'TemplateElement.position' => 'asc'
            )
    );

    public function index($id)
    {

        //check permissions
        $template = $this->TemplateElement->Template->checkAuthorisation($id, $this->Auth->user(), false);
        if (!$this->_isSiteAdmin() && !$template) {
            throw new MethodNotAllowedException('No template with the provided ID exists, or you are not authorised to see it.');
        }

        $templateElements = $this->TemplateElement->find('all', array(
            'conditions' => array(
                'template_id' => $id,
            ),
            'contain' => array(
                'TemplateElementAttribute',
                'TemplateElementText',
                'TemplateElementFile'
            ),
            'order' => array('TemplateElement.position ASC')
        ));
        $this->loadModel('Attribute');
        $this->set('validTypeGroups', $this->Attribute->validTypeGroups);
        $this->set('id', $id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,11 +15,13 @@
 
     public function index($id)
     {
-
+        if (!is_numeric($id)) {
+            throw new MethodNotAllowedException(__('No template with the provided ID exists, or you are not authorised to see it.'));
+        }
         //check permissions
         $template = $this->TemplateElement->Template->checkAuthorisation($id, $this->Auth->user(), false);
         if (!$this->_isSiteAdmin() && !$template) {
-            throw new MethodNotAllowedException('No template with the provided ID exists, or you are not authorised to see it.');
+            throw new MethodNotAllowedException(__('No template with the provided ID exists, or you are not authorised to see it.'));
         }
 
         $templateElements = $this->TemplateElement->find('all', array(
```
