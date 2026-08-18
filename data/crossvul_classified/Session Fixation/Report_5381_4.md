# CrossVul Fix Pair: Session Fixation in php
**Pair ID:** 5381_4
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5381_4`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```php
Lines 76-116 of the vulnerable file.

    function logon($username, $password, &$sessionId)
    {
        global $_POST, $_COOKIE;
        global $strUsernameOrPasswordWrong;

        /**
         * @todo Please check if the following statement is in correct place because
         * it seems illogical that user can get session ID from internal login with
         * a bad username or password.
         */

        if (!$this->_verifyUsernameAndPasswordLength($username, $password)) {
            return false;
        }

        $_POST['username'] = $username;
        $_POST['password'] = $password;

        $_POST['login'] = 'Login';

        $_COOKIE['sessionID'] = uniqid('phpads', 1);
        $_POST['phpAds_cookiecheck'] = $_COOKIE['sessionID'];

        $this->preInitSession();
        if ($this->_internalLogin($username, $password)) {
            // Check if the user has administrator access to Openads.
            if (OA_Permission::isUserLinkedToAdmin()) {

                $this->postInitSession();

                $sessionId = $_COOKIE['sessionID'];
                return true;
            } else {

                $this->raiseError('User must be OA installation admin');
                return false;
            }
        } else {

            $this->raiseError($strUsernameOrPasswordWrong);
            return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,7 +93,8 @@
 
         $_POST['login'] = 'Login';
 
-        $_COOKIE['sessionID'] = uniqid('phpads', 1);
+        unset($_COOKIE['sessionID']);
+        phpAds_SessionStart();
         $_POST['phpAds_cookiecheck'] = $_COOKIE['sessionID'];
 
         $this->preInitSession();
```
