# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5085_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5085_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 43-94 of the vulnerable file.

    private $_cookie_iv = null;

    /**
     * Displays authentication form
     *
     * this function MUST exit/quit the application
     *
     * @global string $conn_error the last connection error
     *
     * @return boolean|void
     */
    public function auth()
    {
        global $conn_error;

        $response = Response::getInstance();
        if ($response->isAjax()) {
            $response->setRequestStatus(false);
            // redirect_flag redirects to the login page
            $response->addJSON('redirect_flag', '1');
            if (defined('TESTSUITE')) {
                return true;
            } else {
                exit;
            }
        }

        /* Perform logout to custom URL */
        if (! empty($_REQUEST['old_usr'])
            && ! empty($GLOBALS['cfg']['Server']['LogoutURL'])
        ) {
            PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['LogoutURL']);
            if (defined('TESTSUITE')) {
                return true;
            } else {
                exit;
            }
        }

        // No recall if blowfish secret is not configured as it would produce
        // garbage
        if ($GLOBALS['cfg']['LoginCookieRecall']
            && ! empty($GLOBALS['cfg']['blowfish_secret'])
        ) {
            $default_user   = $GLOBALS['PHP_AUTH_USER'];
            $default_server = $GLOBALS['pma_auth_server'];
            $autocomplete   = '';
        } else {
            $default_user   = '';
            $default_server = '';
            // skip the IE autocomplete feature.
            $autocomplete   = ' autocomplete="off"';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,18 +60,6 @@
             $response->setRequestStatus(false);
             // redirect_flag redirects to the login page
             $response->addJSON('redirect_flag', '1');
-            if (defined('TESTSUITE')) {
-                return true;
-            } else {
-                exit;
-            }
-        }
-
-        /* Perform logout to custom URL */
-        if (! empty($_REQUEST['old_usr'])
-            && ! empty($GLOBALS['cfg']['Server']['LogoutURL'])
-        ) {
-            PMA_sendHeaderLocation($GLOBALS['cfg']['Server']['LogoutURL']);
             if (defined('TESTSUITE')) {
                 return true;
             } else {
@@ -295,34 +283,6 @@
         }
         // END Swekey Integration
 
-        if (! empty($_REQUEST['old_usr'])) {
-            // The user wants to be logged out
-            // -> delete his choices that were stored in session
-
-            // according to the PHP manual we should do this before the destroy:
-            //$_SESSION = array();
-
-            if (! defined('TESTSUITE')) {
-                session_destroy();
-            }
-            // -> delete password cookie(s)
-            if ($GLOBALS['cfg']['LoginCookieDeleteAll']) {
-                foreach ($GLOBALS['cfg']['Servers'] as $key => $val) {
-                    $GLOBALS['PMA_Config']->removeCookie('pmaPass-' . $key);
-                    if (isset($_COOKIE['pmaPass-' . $key])) {
-                        unset($_COOKIE['pmaPass-' . $key]);
-                    }
-                }
-            } else {
-                $GLOBALS['PMA_Config']->removeCookie(
-                    'pmaPass-' . $GLOBALS['server']
-                );
-                if (isset($_COOKIE['pmaPass-' . $GLOBALS['server']])) {
-                    unset($_COOKIE['pmaPass-' . $GLOBALS['server']]);
-                }
-            }
-        }
-
         if (! empty($_REQUEST['pma_username'])) {
 
             // Verify Captcha if it is required.
@@ -831,4 +791,30 @@
     {
         $this->storePasswordCookie($password);
     }
+
+    /**
+     * Perform logout
+     *
+     * @return void
+     */
+    public function logOut()
+    {
+        // -> delete password cookie(s)
+        if ($GLOBALS['cfg']['LoginCookieDeleteAll']) {
+            foreach ($GLOBALS['cfg']['Servers'] as $key => $val) {
+                $GLOBALS['PMA_Config']->removeCookie('pmaPass-' . $key);
+                if (isset($_COOKIE['pmaPass-' . $key])) {
+                    unset($_COOKIE['pmaPass-' . $key]);
+                }
+            }
+        } else {
+            $GLOBALS['PMA_Config']->removeCookie(
+                'pmaPass-' . $GLOBALS['server']
+            );
+            if (isset($_COOKIE['pmaPass-' . $GLOBALS['server']])) {
+                unset($_COOKIE['pmaPass-' . $GLOBALS['server']]);
+            }
+        }
+        parent::logOut();
+    }
 }
```
