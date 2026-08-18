# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5422_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5422_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 18-58 of the vulnerable file.

require_once MAX_PATH . '/lib/OA/Dll.php';
require_once MAX_PATH . '/www/admin/config.php';
require_once MAX_PATH . '/www/admin/lib-statistics.inc.php';
require_once MAX_PATH . '/www/admin/lib-zones.inc.php';
require_once MAX_PATH . '/lib/OA/Maintenance/Priority.php';

// Register input variables
phpAds_registerGlobal ('value');

if ($value == OA_ENTITY_STATUS_RUNNING) {
    $value = OA_ENTITY_STATUS_PAUSED;
} else {
    $value = OA_ENTITY_STATUS_RUNNING;
}

// Security check
OA_Permission::enforceAccount(OA_ACCOUNT_MANAGER, OA_ACCOUNT_ADVERTISER);
OA_Permission::enforceAccessToObject('clients',   $clientid);
OA_Permission::enforceAccessToObject('campaigns', $campaignid);
OA_Permission::enforceAccessToObject('banners',   $bannerid, true);

if (OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
    if ($value == OA_ENTITY_STATUS_RUNNING) {
        OA_Permission::enforceAllowed(OA_PERM_BANNER_ACTIVATE);
    } else {
        OA_Permission::enforceAllowed(OA_PERM_BANNER_DEACTIVATE);
    }
}


/*-------------------------------------------------------*/
/* Main code                                             */
/*-------------------------------------------------------*/


if (!empty($bannerid))
{
    $doBanners = OA_Dal::factoryDO('banners');
    $doBanners->get($bannerid);
    $bannerName = $doBanners->description;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,6 +35,8 @@
 OA_Permission::enforceAccessToObject('clients',   $clientid);
 OA_Permission::enforceAccessToObject('campaigns', $campaignid);
 OA_Permission::enforceAccessToObject('banners',   $bannerid, true);
+
+OA_Permission::checkSessionToken();
 
 if (OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
     if ($value == OA_ENTITY_STATUS_RUNNING) {
```
