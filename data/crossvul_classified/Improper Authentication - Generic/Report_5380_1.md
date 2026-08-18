# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 5380_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5380_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php

/*
+---------------------------------------------------------------------------+
| Revive Adserver                                                           |
| http://www.revive-adserver.com                                            |
|                                                                           |
| Copyright: See the COPYRIGHT.txt file.                                    |
| License: GPLv2 or later, see the LICENSE.txt file.                        |
+---------------------------------------------------------------------------+
*/

require_once MAX_PATH . '/lib/max/Plugin/Translation.php';
require_once LIB_PATH . '/Plugin/Component.php';
require_once 'Date.php';
require_once MAX_PATH . '/lib/max/language/Loader.php';
require_once MAX_PATH . '/lib/pear/HTML/QuickForm/Rule/Email.php';

Language_Loader::load('settings');

/**
 * Plugins_Authentication is an parent class for Authentication plugins
 *
 * @package    OpenXPlugin
 * @subpackage Authentication
 */
class Plugins_Authentication extends OX_Component
{
    /**
     * Array to keep a reference to signup errors (if any)
     *
     * @var array
     */
    var $aSignupErrors = array();

    var $aValidationErrors = array();

    /**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,6 +15,7 @@
 require_once 'Date.php';
 require_once MAX_PATH . '/lib/max/language/Loader.php';
 require_once MAX_PATH . '/lib/pear/HTML/QuickForm/Rule/Email.php';
+require_once MAX_PATH . '/lib/OA/DB/AdvisoryLock.php';
 
 Language_Loader::load('settings');
 
@@ -98,16 +99,55 @@
      */
     function checkPassword($username, $password)
     {
+        // Introduce a random delay in case of failures, as recommended by:
+        // https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks
+        //
+        // The base delay is 1-5 seconds.
+        $waitMs = mt_rand(1000, 5000);
+
+        $oLock = OA_DB_AdvisoryLock::factory();
+
+        // Username check is case insensitive
+        $username = strtolower($username);
+
+        // Try to acquire an excusive advisory lock for the username
+        $lock = $oLock->get('auth.'.md5($username));
+
+        if (!$lock) {
+            // We couldn't acquire the lock immediately, which means that
+            // another authentication process for the same username is underway.
+            //
+            // This might mean that the account is being targeted by a
+            // multi-threaded brute force attack, so we try to discourage such
+            // behaviour by increasing the delay time by 4x.
+            //
+            // However, if the actual user tries to log in while their account
+            // is being attacked, we will allow them in, they'd just have to
+            // be patient (max 20 seconds).
+            usleep($waitMs * 4000);
+        }
+
         $doUser = OA_Dal::factoryDO('users');
-        $doUser->username = strtolower($username);
+        $doUser->username = $username;
         $doUser->password = md5($password);
+
         $doUser->find();
 
         if ($doUser->fetch()) {
+            $oLock->release();
+
             return $doUser;
-        } else {
-            return false;
-        }
+        }
+
+        if ($lock) {
+            // The password was wrong, but no other login attempt was in place
+            // so we apply just the base delay time.
+            usleep($waitMs * 1000);
+        }
+
+        $oLock->release();
+
+        return false;
     }
 
     /**
@@ -517,4 +557,7 @@
     }
 }
 
-?>
+
+class Plugins_Authentication_Exception extends Exception
+{
+}
```
