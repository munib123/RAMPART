# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5423_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 26-66 of the vulnerable file.

phpAds_registerGlobal ('campaignid', 'clientid', 'newclientid', 'returnurl', 'duplicate');

// Security check
OA_Permission::enforceAccount(OA_ACCOUNT_MANAGER);

if(!empty($duplicate)) {
    OA_Permission::enforceAccessToObject('clients',   $clientid, false, OA_Permission::OPERATION_VIEW);
    OA_Permission::enforceAccessToObject('campaigns', $campaignid, false, OA_Permission::OPERATION_DUPLICATE);
}
else if (!empty($newclientid)) {
    OA_Permission::enforceAccessToObject('clients',   $clientid, false, OA_Permission::OPERATION_VIEW);
    OA_Permission::enforceAccessToObject('campaigns', $campaignid, false, OA_Permission::OPERATION_MOVE);
    OA_Permission::enforceAccessToObject('clients', $newclientid, false, OA_Permission::OPERATION_EDIT);
}

/*-------------------------------------------------------*/
/* Main code                                             */
/*-------------------------------------------------------*/

if (!empty($campaignid)) {
    if (!empty($duplicate)) {
    	// Duplicate the campaign
    	$doCampaigns = OA_Dal::factoryDO('campaigns');
    	$doCampaigns->get($campaignid);
        $oldName = $doCampaigns->campaignname;
    	$newCampaignId = $doCampaigns->duplicate();

        if ($newCampaignId) {
            // Queue confirmation message
            $newName = $doCampaigns->campaignname;
            $translation = new OX_Translation();
            $translated_message = $translation->translate ( $GLOBALS['strCampaignHasBeenDuplicated'],
                array(MAX::constructURL(MAX_URL_ADMIN, "campaign-edit.php?clientid=$clientid&campaignid=$campaignid"),
                    htmlspecialchars($oldName),
                    MAX::constructURL(MAX_URL_ADMIN, "campaign-edit.php?clientid=$clientid&campaignid=$newCampaignId"),
                    htmlspecialchars($newName))
            );
            OA_Admin_UI::queueMessage($translated_message, 'local', 'confirm', 0);

            Header ("Location: {$returnurl}?clientid={$clientid}&campaignid={$newCampaignId}");
            exit;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,8 @@
 /*-------------------------------------------------------*/
 
 if (!empty($campaignid)) {
+    OA_Permission::checkSessionToken();
+
     if (!empty($duplicate)) {
     	// Duplicate the campaign
     	$doCampaigns = OA_Dal::factoryDO('campaigns');
```
