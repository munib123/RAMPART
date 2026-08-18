# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5422_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5422_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 31-71 of the vulnerable file.

OA_Permission::enforceAccount(OA_ACCOUNT_MANAGER);
OA_Permission::enforceAccessToObject('clients',   $clientid);
OA_Permission::enforceAccessToObject('campaigns', $campaignid);
OA_Permission::enforceAccessToObject('banners',   $bannerid);

/*-------------------------------------------------------*/
/* Store preferences									 */
/*-------------------------------------------------------*/
$session['prefs']['inventory_entities'][OA_Permission::getEntityId()]['clientid'] = $clientid;
$session['prefs']['inventory_entities'][OA_Permission::getEntityId()]['campaignid'][$clientid] = $campaignid;
phpAds_SessionDataStore();

// Initialise some parameters
$pageName = basename($_SERVER['SCRIPT_NAME']);
$tabindex = 1;
$aEntities = array('clientid' => $clientid, 'campaignid' => $campaignid, 'bannerid' => $bannerid);

if (!empty($action)) {
    $acl = MAX_AclAdjust($acl, $action);
} elseif (!empty($submit)) {
    $acl = (isset($acl)) ? $acl : array();

    // Only save when inputs are valid
    if (OX_AclCheckInputsFields($acl, $pageName) === true) {
        $aBannerPrev = MAX_cacheGetAd($bannerid, false);
        MAX_AclSave($acl, $aEntities);

        $block = _initCappingVariables($time, $cap, $session_capping);

        $values = array();
        $acls_updated = false;
        $now = OA::getNow();

        if ($aBannerPrev['block_ad'] <> $block) {
            $values['block'] = $block;
            $acls_updated = ($block == 0) ? true : $acls_updated;
        }
        if ($aBannerPrev['cap_ad'] <> $cap) {
            $values['capping'] = $cap;
            $acls_updated = ($cap == 0) ? true : $acls_updated;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,6 +48,8 @@
 if (!empty($action)) {
     $acl = MAX_AclAdjust($acl, $action);
 } elseif (!empty($submit)) {
+    OA_Permission::checkSessionToken();
+
     $acl = (isset($acl)) ? $acl : array();
 
     // Only save when inputs are valid
```
