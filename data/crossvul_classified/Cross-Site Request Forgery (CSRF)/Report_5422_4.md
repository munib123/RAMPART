# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5422_4
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5422_4`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 17-57 of the vulnerable file.

require_once MAX_PATH . '/www/admin/lib-maintenance-priority.inc.php';
require_once MAX_PATH . '/lib/OA/Dal.php';
require_once MAX_PATH . '/www/admin/config.php';
require_once MAX_PATH . '/www/admin/lib-statistics.inc.php';
require_once MAX_PATH . '/www/admin/lib-storage.inc.php';
require_once MAX_PATH . '/www/admin/lib-swf.inc.php';
require_once MAX_PATH . '/www/admin/lib-banner.inc.php';
require_once MAX_PATH . '/www/admin/lib-zones.inc.php';

// Register input variables
phpAds_registerGlobalUnslashed('convert', 'cancel', 'compress', 'convert_links',
                       'chosen_link', 'overwrite_link', 'overwrite_target',
                       'overwrite_source');


// Security check
OA_Permission::enforceAccount(OA_ACCOUNT_MANAGER, OA_ACCOUNT_ADVERTISER);
OA_Permission::enforceAccessToObject('clients',   $clientid);
OA_Permission::enforceAccessToObject('campaigns', $campaignid);
OA_Permission::enforceAccessToObject('banners',   $bannerid);

if (OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
    OA_Permission::enforceAllowed(OA_PERM_BANNER_EDIT);
}

/*-------------------------------------------------------*/
/* Process submitted form                                */
/*-------------------------------------------------------*/

if (isset($convert)) {
    $doBanners = OA_Dal::factoryDO('banners');
    $doBanners->get($bannerid);
    $row = $doBanners->toArray();

    if ($row['storagetype'] == 'sql' || $row['storagetype'] == 'web') {
        $swf_file = phpAds_ImageRetrieve ($row['storagetype'], $row['filename']);
    }
    if ($swf_file) {
        if (phpAds_SWFVersion($swf_file) >= 3 && phpAds_SWFInfo($swf_file)) {
            // SWF's requiring player version 6+ which are already compressed should stay compressed
            if (phpAds_SWFVersion($swf_file) >= 6 && phpAds_SWFCompressed($swf_file)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,8 @@
 OA_Permission::enforceAccessToObject('clients',   $clientid);
 OA_Permission::enforceAccessToObject('campaigns', $campaignid);
 OA_Permission::enforceAccessToObject('banners',   $bannerid);
+
+    OA_Permission::checkSessionToken();
 
 if (OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
     OA_Permission::enforceAllowed(OA_PERM_BANNER_EDIT);
```
