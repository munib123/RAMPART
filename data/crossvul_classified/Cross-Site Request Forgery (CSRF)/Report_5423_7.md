# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5423_7
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_7`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 20-60 of the vulnerable file.

/*-------------------------------------------------------*/
/* Main code                                             */
/*-------------------------------------------------------*/

// Send header with charset info
header ("Content-Type: text/html".(isset($phpAds_CharSet) && $phpAds_CharSet != "" ? "; charset=".$phpAds_CharSet : ""));

require_once MAX_PATH . '/lib/OA/Admin/Template.php';
require_once MAX_PATH . '/lib/OA/Admin/UI/CampaignZoneLink.php';

phpAds_registerGlobalUnslashed('action', 'campaignid', 'allSelected',
        'text-linked', 'text-available');

$agencyId   = OA_Permission::getAgencyId();
$oDalZones  = OA_Dal::factoryDAL('zones');
$action     = $GLOBALS["action"];
$campaignId = $GLOBALS['campaignid'];

OA_Permission::enforceAccount ( OA_ACCOUNT_MANAGER );
OA_Permission::enforceAccessToObject ( 'campaigns', $campaignid );

$aZonesIds = array();
$aZonesIdsHash = array();
foreach ($_REQUEST['ids'] as $zone) {
    if (substr($zone, 0, 1) == 'z') {
        $aZonesIds[] = (int) substr($zone, 1);
        $aZonesIdsHash[(int) substr($zone, 1)] = "x";
    }
}

// If we're requested to link all matching zones, we need to determine the ids to link
// Ideally, there should be a DAL method to that directly. Note that we're replacing
// only the $aZonesIds array here, and keeping $aZonesIdsHash populated based on the
// zone ids from the request. This way, zones with ids from the request will get
// higlighted as "just linked". It doesn't make to put all zone ids in $aZonesIdsHash as
// only
if ($GLOBALS['allSelected'] == 'true') {
    $aZonesIds = array();
    $link = ($action == 'link');
    $text = ($link ? $GLOBALS['text-available'] : $GLOBALS['text-linked']);
    $websites = $oDalZones->getWebsitesAndZones($agencyId, $campaignId, !$link, $text);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,8 @@
 
 OA_Permission::enforceAccount ( OA_ACCOUNT_MANAGER );
 OA_Permission::enforceAccessToObject ( 'campaigns', $campaignid );
+
+OA_Permission::checkSessionToken();
 
 $aZonesIds = array();
 $aZonesIdsHash = array();
@@ -103,4 +105,5 @@
 };
 echo "<!--result-info-end-->";
 
-?>
+// CSRF Token
+echo "<!--token-value-start-->".phpAds_SessionGetToken()."<!--token-value-end-->";
```
