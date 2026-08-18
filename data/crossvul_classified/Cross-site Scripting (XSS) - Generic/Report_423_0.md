# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 423_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `423_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 16-57 of the vulnerable file.

    	$t = Zend_Registry::get('translate');
    	$this->view->headTitle($t->_('login'));
    	$this->view->layout()->setLayout('basic');
    	
    	$auth = Zend_Auth::getInstance();
    	if ($auth->hasIdentity()) {
            $this->_redirect('/index');
    	}

    	$request = $this->getRequest(); 
        // determine the page the user was originally trying to request 
        $redirect = $request->getPost('redirect'); 
        if (strlen($redirect) == 0) 
            $redirect = $request->getServer('REQUEST_URI'); 
        if (strlen($redirect) == 0) 
            $redirect = '/index';


        $request = $this->getRequest();
        $form    = new Default_Form_Login();
        if ($this->getRequest()->getParam('message')) {
        	$form->addErrorMessage($this->getRequest()->getParam('message'));
        }
        
        if ($this->getRequest()->isPost() && $form->isValid($request->getPost())) {
        	
    	    $authAdapter = new Zend_Auth_Adapter_DbTable(
                          Zend_Registry::get('writedb'),
                          'administrator',
                          'username',
                          'password',
                          'ENCRYPT(?, SUBSTRING(password,1,2))'
                       );   
            $authAdapter2 = new Zend_Auth_Adapter_DbTable(
                          Zend_Registry::get('writedb'),
                          'administrator',
                          'username',
                          'password',
                          'ENCRYPT(?, SUBSTR(password, 1,12))'
                       );   
            ## This one should work for most crypt sheme, principaly crypt-sha512, regarldess of the salt length
            $authAdapter4 = new Zend_Auth_Adapter_DbTable(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,8 +33,10 @@
 
         $request = $this->getRequest();
         $form    = new Default_Form_Login();
-        if ($this->getRequest()->getParam('message')) {
-        	$form->addErrorMessage($this->getRequest()->getParam('message'));
+        
+        // Display only loggedOut message
+        if ($this->getRequest()->getParam('message') == "loggedOut") {
+        	$form->addErrorMessage(htmlspecialchars($this->getRequest()->getParam('message')));
         }
         
         if ($this->getRequest()->isPost() && $form->isValid($request->getPost())) {
```
