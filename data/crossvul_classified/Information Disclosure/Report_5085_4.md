# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5085_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5085_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 32-83 of the vulnerable file.

            $response->setRequestStatus(false);
            // reload_flag removes the token parameter from the URL and reloads
            $response->addJSON('reload_flag', '1');
            if (defined('TESTSUITE')) {
                return true;
            } else {
                exit;
            }
        }

        return $this->authForm();
    }

    /**
     * Displays authentication form
     *
     * @return boolean
     */
    public function authForm()
    {
        /* Perform logout to custom URL */
        if (!empty($_REQUEST['old_usr'])
            && !empty($GLOBALS['cfg']['Server']['LogoutURL'])
        ) {
            PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['LogoutURL']);
            if (!defined('TESTSUITE')) {
                exit;
            } else {
                return false;
            }
        }

        if (empty($GLOBALS['cfg']['Server']['auth_http_realm'])) {
            if (empty($GLOBALS['cfg']['Server']['verbose'])) {
                $server_message = $GLOBALS['cfg']['Server']['host'];
            } else {
                $server_message = $GLOBALS['cfg']['Server']['verbose'];
            }
            $realm_message = 'phpMyAdmin ' . $server_message;
        } else {
            $realm_message = $GLOBALS['cfg']['Server']['auth_http_realm'];
        }

        $response = Response::getInstance();

        // remove non US-ASCII to respect RFC2616
        $realm_message = preg_replace('/[^\x20-\x7e]/i', '', $realm_message);
        $response->header('WWW-Authenticate: Basic realm="' . $realm_message . '"');
        $response->header('HTTP/1.0 401 Unauthorized');
        if (php_sapi_name() !== 'cgi-fcgi') {
            $response->header('status: 401 Unauthorized');
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,18 +49,6 @@
      */
     public function authForm()
     {
-        /* Perform logout to custom URL */
-        if (!empty($_REQUEST['old_usr'])
-            && !empty($GLOBALS['cfg']['Server']['LogoutURL'])
-        ) {
-            PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['LogoutURL']);
-            if (!defined('TESTSUITE')) {
-                exit;
-            } else {
-                return false;
-            }
-        }
-
         if (empty($GLOBALS['cfg']['Server']['auth_http_realm'])) {
             if (empty($GLOBALS['cfg']['Server']['verbose'])) {
                 $server_message = $GLOBALS['cfg']['Server']['host'];
@@ -262,4 +250,14 @@
 
         return true;
     }
+
+    /**
+     * Returns URL for login form.
+     *
+     * @return string
+     */
+    public function getLoginFormURL()
+    {
+        return './index.php?old_usr=' . $GLOBALS['PHP_AUTH_USER'];
+    }
 }
```
