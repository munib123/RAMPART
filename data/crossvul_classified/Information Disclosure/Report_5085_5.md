# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5085_5
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5085_5`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 11-55 of the vulnerable file.

use PMA\libraries\plugins\AuthenticationPlugin;
use PMA;

/**
 * Handles the SignOn authentication method
 *
 * @package PhpMyAdmin-Authentication
 */
class AuthenticationSignon extends AuthenticationPlugin
{
    /**
     * Displays authentication form
     *
     * @return boolean   always true (no return indeed)
     */
    public function auth()
    {
        unset($_SESSION['LAST_SIGNON_URL']);
        if (empty($GLOBALS['cfg']['Server']['SignonURL'])) {
            PMA_fatalError('You must set SignonURL!');
        } elseif (!empty($_REQUEST['old_usr'])
            && !empty($GLOBALS['cfg']['Server']['LogoutURL'])
        ) {
            /* Perform logout to custom URL */
            PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['LogoutURL']);
        } else {
            PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['SignonURL']);
        }

        if (!defined('TESTSUITE')) {
            exit();
        } else {
            return false;
        }
    }

    /**
     * Gets advanced authentication settings
     *
     * @global  string $PHP_AUTH_USER        the username if register_globals is on
     * @global  string $PHP_AUTH_PW          the password if register_globals is on
     *
     * @return boolean   whether we get authentication settings or not
     */
    public function authCheck()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,11 +28,6 @@
         unset($_SESSION['LAST_SIGNON_URL']);
         if (empty($GLOBALS['cfg']['Server']['SignonURL'])) {
             PMA_fatalError('You must set SignonURL!');
-        } elseif (!empty($_REQUEST['old_usr'])
-            && !empty($GLOBALS['cfg']['Server']['LogoutURL'])
-        ) {
-            /* Perform logout to custom URL */
-            PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['LogoutURL']);
         } else {
             PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['SignonURL']);
         }
@@ -81,9 +76,6 @@
 
         /* No configuration updates */
         $single_signon_cfgupdate = array();
-
-        /* Are we requested to do logout? */
-        $do_logout = !empty($_REQUEST['old_usr']);
 
         /* Handle script based auth */
         if (!empty($script_name)) {
@@ -117,18 +109,10 @@
 
             /* Grab credentials if they exist */
             if (isset($_SESSION['PMA_single_signon_user'])) {
-                if ($do_logout) {
-                    $PHP_AUTH_USER = '';
-                } else {
-                    $PHP_AUTH_USER = $_SESSION['PMA_single_signon_user'];
-                }
+                $PHP_AUTH_USER = $_SESSION['PMA_single_signon_user'];
             }
             if (isset($_SESSION['PMA_single_signon_password'])) {
-                if ($do_logout) {
-                    $PHP_AUTH_PW = '';
-                } else {
-                    $PHP_AUTH_PW = $_SESSION['PMA_single_signon_password'];
-                }
+                $PHP_AUTH_PW = $_SESSION['PMA_single_signon_password'];
             }
             if (isset($_SESSION['PMA_single_signon_host'])) {
                 $single_signon_host = $_SESSION['PMA_single_signon_host'];
```
