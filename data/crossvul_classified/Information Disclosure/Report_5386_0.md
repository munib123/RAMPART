# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5386_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5386_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 90-134 of the vulnerable file.

        }
        $this->pageFooter();
    }

    /**
     * Display an entire page with the password recovery form.
     *
     * This method, combined with handleGet allows semantic, REST-style
     * actions.
     */
    function handlePost($vars)
    {
        OA_Permission::checkSessionToken();

        $this->pageHeader();
        if (empty($vars['id'])) {
            if (empty($vars['email'])) {
                $this->displayRecoveryRequestForm($GLOBALS['strEmailRequired']);
            } else {
                $sent = $this->sendRecoveryEmail(stripslashes($vars['email']));
                if ($sent) {
                    $this->displayMessage($GLOBALS['strNotifyPageMessage']);
                } else {
                $this->displayRecoveryRequestForm($GLOBALS['strPwdRecEmailNotFound']);
                }
            }
        } else {
            if (empty($vars['newpassword']) || empty($vars['newpassword2']) || $vars['newpassword'] != $vars['newpassword2']) {
                $this->displayRecoveryResetForm($vars['id'], $GLOBALS['strNotSamePasswords']);
            } elseif ($this->_dal->checkRecoveryId($vars['id'])) {
                $userId = $this->_dal->saveNewPasswordAndLogin($vars['id'], stripslashes($vars['newpassword']));
                OX_Admin_Redirect::redirect();
            } else {
                $this->displayRecoveryRequestForm($GLOBALS['strPwdRecWrongId']);
            }
        }
        $this->pageFooter();
    }

    /**
     * Display a message
     *
     * @param string message to be displayed
     */
    function displayMessage($message)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,11 +107,9 @@
                 $this->displayRecoveryRequestForm($GLOBALS['strEmailRequired']);
             } else {
                 $sent = $this->sendRecoveryEmail(stripslashes($vars['email']));
-                if ($sent) {
-                    $this->displayMessage($GLOBALS['strNotifyPageMessage']);
-                } else {
-                $this->displayRecoveryRequestForm($GLOBALS['strPwdRecEmailNotFound']);
-                }
+
+                // Always pretend an email was sent, even if not to avoid information disclosure
+                $this->displayMessage($GLOBALS['strNotifyPageMessage']);
             }
         } else {
             if (empty($vars['newpassword']) || empty($vars['newpassword2']) || $vars['newpassword'] != $vars['newpassword2']) {
```
