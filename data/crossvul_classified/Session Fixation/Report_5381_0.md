# CrossVul Fix Pair: Session Fixation in php
**Pair ID:** 5381_0
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5381_0`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```php
Lines 68-108 of the vulnerable file.

        if (!is_callable($redirectCallback)) {
            // Set the default callback
            $redirectCallback = array('OA_Auth', 'checkRedirect');
        }

        if (call_user_func($redirectCallback)) {
            header('location: http://'.$aConf['webpath']['admin']);
            exit();
        }

        if (defined('OA_SKIP_LOGIN')) {
            return OA_Auth::getFakeSessionData();
        }

        if (OA_Auth::suppliedCredentials()) {
            $doUser = OA_Auth::authenticateUser();

            if (!$doUser) {
                OA_Auth::restart($GLOBALS['strUsernameOrPasswordWrong']);
            }

            return OA_Auth::getSessionData($doUser);
        }

        OA_Auth::restart();
    }

    /**
     * A method to logout and redirect to the correct URL
     *
     * @static
     *
     * @todo Fix when preferences are ready and logout url is stored into the
     * preferences table
     */
    function logout()
    {
        $authPlugin = OA_Auth::staticGetAuthPlugin();
        $authPlugin->logout();
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,6 +86,9 @@
                 OA_Auth::restart($GLOBALS['strUsernameOrPasswordWrong']);
             }
 
+            // Regenerate session ID now
+            phpAds_SessionRegenerateId();
+
             return OA_Auth::getSessionData($doUser);
         }
 
@@ -190,7 +193,7 @@
      */
     function restart($sMessage = '')
     {
-        $_COOKIE['sessionID'] = phpAds_SessionStart();
+        $_COOKIE['sessionID'] = phpAds_SessionRegenerateId();
         OA_Auth::displayLogin($sMessage, $_COOKIE['sessionID']);
     }
 
```
