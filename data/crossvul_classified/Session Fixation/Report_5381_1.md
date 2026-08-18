# CrossVul Fix Pair: Session Fixation in php
**Pair ID:** 5381_1
**Vulnerability Class:** Session Fixation
**CWE:** CWE-384
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5381_1`)

## Vulnerability Information & PoC

## Description
Session Fixation - Such a scenario is commonly observed when: A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the ...

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.

| Copyright: See the COPYRIGHT.txt file.                                    |
| License: GPLv2 or later, see the LICENSE.txt file.                        |
+---------------------------------------------------------------------------+
*/

require_once MAX_PATH . '/lib/OA/Auth.php';

/**
 * A class to deal with login and auto-login features during install/upgrade
 */
class OA_Upgrade_Login
{
    /**
     * Check administrator login during the upgrade steps
     *
     * @return boolean True if login succeded
     */
    function checkLogin()
    {
        // Clean up session
        $GLOBALS['session'] = array();

        // Detection needs to happen every time to make sure that database parameters are
        $oUpgrader = new OA_Upgrade();
        $openadsDetected = $oUpgrader->detectOpenads(true) ||
            $oUpgrader->existing_installation_status == OA_STATUS_CURRENT_VERSION;

        // Sequentially check, to avoid useless work
        if (!$openadsDetected) {
            if (!($panDetected = $oUpgrader->detectPAN(true))) {
                if (!($maxDetected = $oUpgrader->detectMAX(true))) {
                    if (!($max01Detected = $oUpgrader->detectMAX01(true))) {
                        // No upgrade-able version detected, return
                        return false;
                    }
                }
            }
        }

        phpAds_SessionStart();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
     function checkLogin()
     {
         // Clean up session
-        $GLOBALS['session'] = array();
+        phpAds_clearSession();
 
         // Detection needs to happen every time to make sure that database parameters are
         $oUpgrader = new OA_Upgrade();
@@ -93,6 +93,7 @@
             $doUser->joinAdd($doAUA);
             $doUser->find();
             if ($doUser->fetch()) {
+                phpAds_SessionRegenerateId();
                 phpAds_SessionDataRegister(OA_Auth::getSessionData($doUser));
                 phpAds_SessionDataStore();
             }
@@ -106,6 +107,8 @@
         $aCredentials = $oPlugin->_getCredentials(false);
 
         if (!PEAR::isError($aCredentials)) {
+            phpAds_SessionRegenerateId();
+
             $doUser = $oPlugin->checkPassword($aCredentials['username'], $aCredentials['password']);
 
             if ($doUser) {
@@ -140,6 +143,8 @@
                 $aCredentials = $oPlugin->_getCredentials(false);
 
                 if (!PEAR::isError($aCredentials)) {
+                    phpAds_SessionRegenerateId();
+
                     if (strtolower($aPref['admin']) == strtolower($aCredentials['username']) &&
                         $aPref['admin_pw'] == md5($aCredentials['password']))
                     {
```
