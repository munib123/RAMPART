# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5383_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5383_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 82-122 of the vulnerable file.

    {
        $this->pageHeader();
        if (empty($vars['id'])) {
            $this->displayRecoveryRequestForm();
        } elseif ($this->_dal->checkRecoveryId($vars['id'])) {
            $this->displayRecoveryResetForm($vars['id']);
        } else {
            OX_Admin_Redirect::redirect();
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,6 +99,8 @@
      */
     function handlePost($vars)
     {
+        OA_Permission::checkSessionToken();
+
         $this->pageHeader();
         if (empty($vars['id'])) {
             if (empty($vars['email'])) {
@@ -152,6 +154,8 @@
 
         echo "<form method='post' action='password-recovery.php'>\n";
 
+        echo "<input type='hidden' name='token' value='".phpAds_SessionGetToken()."'/>\n";
+
         echo "<div class='install'>".$GLOBALS['strPwdRecEnterEmail']."</div>";
         echo "<table cellpadding='0' cellspacing='0' border='0'>";
         echo "<tr><td colspan='2'><img src='" . OX::assetPath() . "/images/break-el.gif' width='400' height='1' vspace='8'></td></tr>";
@@ -177,6 +181,7 @@
 
         echo "<form method='post' action='password-recovery.php'>\n";
         echo "<input type='hidden' name='id' value=\"".htmlspecialchars($id)."\" />";
+        echo "<input type='hidden' name='token' value='".phpAds_SessionGetToken()."'/>\n";
 
         echo "<div class='install'>".$GLOBALS['strPwdRecEnterPassword']."</div>";
         echo "<table cellpadding='0' cellspacing='0' border='0'>";
```
