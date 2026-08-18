# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1743_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1743_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 74-114 of the vulnerable file.

if (!isset($agencyid))      $agencyid = (OA_Permission::isAccount(OA_ACCOUNT_ADMIN)) ? '' : OA_Permission::getAgencyId();
if (!isset($bannerid))      $bannerid = '';
if (!isset($campaignid))    $campaignid = '';
if (!isset($channelid))     $channelid = '';
if (!isset($clientid))      $clientid = (OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) ? OA_Permission::getEntityId() : '';
if (!isset($day))           $day = '';
if (!isset($trackerid))     $trackerid = '';
if (!isset($userlogid))     $userlogid = '';
if (!isset($zoneid))        $zoneid = '';

/**
 * Starts or continue existing session
 *
 * @param unknown_type $checkRedirectFunc
 */
function OA_Start($checkRedirectFunc = null)
{
    $conf = $GLOBALS['_MAX']['CONF'];
    global $session;

    // XXX: Why not try loading session data when OpenX is not installed?
    //if ($conf['openads']['installed'])
    if (OA_INSTALLATION_STATUS == OA_INSTALLATION_STATUS_INSTALLED)
    {
        phpAds_SessionDataFetch();
    }
    if (!OA_Auth::isLoggedIn() || OA_Auth::suppliedCredentials()) {
        // Required files
        include_once MAX_PATH . '/lib/max/language/Loader.php';
        // Load the required language files
        Language_Loader::load('default');

        phpAds_SessionDataRegister(OA_Auth::login($checkRedirectFunc));

        $aPlugins = OX_Component::getListOfRegisteredComponentsForHook('afterLogin');
        foreach ($aPlugins as $i => $id)
        {
            if ($obj = OX_Component::factoryByComponentIdentifier($id))
            {
                $obj->afterLogin();
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,6 +91,11 @@
     $conf = $GLOBALS['_MAX']['CONF'];
     global $session;
 
+    // Send no cache headers
+    MAX_header('Pragma: no-cache');
+    MAX_header('Cache-Control: no-cache, no-store, must-revalidate');
+    MAX_header('Expires: 0');
+
     // XXX: Why not try loading session data when OpenX is not installed?
     //if ($conf['openads']['installed'])
     if (OA_INSTALLATION_STATUS == OA_INSTALLATION_STATUS_INSTALLED)
```
