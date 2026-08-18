# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 1742_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1742_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 108-149 of the vulnerable file.


        $this->registerJQueryRuleAdaptor("unique", MAX_PATH.'/lib/OA/Admin/UI/component/rule/QuickFormUniqueRuleAdaptor.php',
            'OA_Admin_UI_Rule_JQueryUniqueRule');

        $this->registerJQueryRuleAdaptor("equal", MAX_PATH.'/lib/OA/Admin/UI/component/rule/QuickFormEqualRuleAdaptor.php',
            'OA_Admin_UI_Rule_JQueryEqualRule');

        //register element decorators
        $this->registerElementDecorator('tag', MAX_PATH.'/lib/OA/Admin/UI/component/decorator/HTMLTagDecorator.php',
            'OA_Admin_UI_HTMLTagDecorator');
        $this->registerElementDecorator('process', MAX_PATH.'/lib/OA/Admin/UI/component/decorator/ProcessingDecorator.php',
            'OA_Admin_UI_ProcessingDecorator');


        //apply flat class
        $this->setAttribute("class", "flat");

        //trim spaces from all data sent by the user
        $this->applyFilter('__ALL__', 'trim');

        $this->addElement('hidden', 'token', phpAds_SessionGetToken());
        $this->addRule('token', 'Invalid request token', 'callback', 'phpAds_SessionValidateToken');
    }

    function validate()
    {
        $ret = parent::validate();

        if (!$ret) {
            // The form returned an error. We need to generate a new CSRF token, in any.
            $token = $this->getElement('token');
            if (!empty($token)) {
                $token->setValue(phpAds_SessionGetToken());
            }
        }

        return $ret;
    }

    /**
     * Registers new JQuery QuickForm rule adaptor. Registered adaptors should
     * implement OA_Admin_UI_Rule_QuickFormToJQueryRuleAdaptor
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,8 +125,11 @@
         //trim spaces from all data sent by the user
         $this->applyFilter('__ALL__', 'trim');
 
-        $this->addElement('hidden', 'token', phpAds_SessionGetToken());
-        $this->addRule('token', 'Invalid request token', 'callback', 'phpAds_SessionValidateToken');
+        if (!defined('phpAds_installing')) {
+            $this->addElement('hidden', 'token', phpAds_SessionGetToken());
+            $this->addRule('token', 'Missing request token', 'required');
+            $this->addRule('token', 'Invalid request token', 'callback', 'phpAds_SessionValidateToken');
+        }
     }
 
     function validate()
@@ -136,7 +139,7 @@
         if (!$ret) {
             // The form returned an error. We need to generate a new CSRF token, in any.
             $token = $this->getElement('token');
-            if (!empty($token)) {
+            if (!empty($token) && !PEAR::isError($token)) {
                 $token->setValue(phpAds_SessionGetToken());
             }
         }
```
