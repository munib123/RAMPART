# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5085_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5085_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 36-76 of the vulnerable file.

     */
    abstract public function authSetUser();

    /**
     * Stores user credentials after successful login.
     *
     * @return void
     */
    public function storeUserCredentials()
    {
    }

    /**
     * User is not allowed to login to MySQL -> authentication failed
     *
     * @return boolean
     */
    abstract public function authFails();

    /**
     * Returns error message for failed authentication.
     *
     * @return string
     */
    public function getErrorMessage()
    {
        if (!empty($GLOBALS['login_without_password_is_forbidden'])) {
            return __(
                'Login without a password is forbidden by configuration'
                . ' (see AllowNoPassword)'
            );
        } elseif (!empty($GLOBALS['allowDeny_forbidden'])) {
            return __('Access denied!');
        } elseif (!empty($GLOBALS['no_activity'])) {
            return sprintf(
                __('No activity within %s seconds; please log in again.'),
                $GLOBALS['cfg']['LoginCookieValidity']
            );
        } else {
            $dbi_error = $GLOBALS['dbi']->getError();
            if (!empty($dbi_error)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,6 +53,46 @@
     abstract public function authFails();
 
     /**
+     * Perform logout
+     *
+     * @return void
+     */
+    public function logOut()
+    {
+        global $PHP_AUTH_USER, $PHP_AUTH_PW;
+
+        /* Obtain redirect URL (before doing logout) */
+        if (! empty($GLOBALS['cfg']['Server']['LogoutURL'])) {
+            $redirect_url = $GLOBALS['cfg']['Server']['LogoutURL'];
+        } else {
+            $redirect_url = $this->getLoginFormURL();
+        }
+
+        /* Clear credentials */
+        $PHP_AUTH_USER = '';
+        $PHP_AUTH_PW = '';
+
+        /* delete user's choices that were stored in session */
+        $_SESSION = array();
+        if (!defined('TESTSUITE')) {
+            session_destroy();
+        }
+
+        /* Redirect to login form (or configured URL) */
+        PMA_sendHeaderLocation($redirect_url);
+    }
+
+    /**
+     * Returns URL for login form.
+     *
+     * @return string
+     */
+    public function getLoginFormURL()
+    {
+        return './index.php';
+    }
+
+    /**
      * Returns error message for failed authentication.
      *
      * @return string
```
