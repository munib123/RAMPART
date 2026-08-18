# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 5380_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5380_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 66-106 of the vulnerable file.

        $aConf = $GLOBALS['_MAX']['CONF'];

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
                sleep(3);
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,7 +83,6 @@
             $doUser = OA_Auth::authenticateUser();
 
             if (!$doUser) {
-                sleep(3);
                 OA_Auth::restart($GLOBALS['strUsernameOrPasswordWrong']);
             }
 
```
