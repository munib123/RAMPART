# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5422_6
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5422_6`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.


// Register input variables
phpAds_registerGlobal (
     'duplicate'
    ,'moveto'
    ,'returnurl'
);


// Security check
OA_Permission::enforceAccount(OA_ACCOUNT_MANAGER);
OA_Permission::enforceAccessToObject('clients', $clientid);
OA_Permission::enforceAccessToObject('trackers', $trackerid);

/*-------------------------------------------------------*/
/* Main code                                             */
/*-------------------------------------------------------*/

if (!empty($trackerid))
{
    if (!empty($moveto))
    {
        // Delete any campaign-tracker links
        $doCampaign_trackers = OA_Dal::factoryDO('campaigns_trackers');
        $doCampaign_trackers->trackerid = $trackerid;
        $doCampaign_trackers->delete();

        // Move the tracker
        $doTrackers = OA_Dal::factoryDO('trackers');
        if ($doTrackers->get($trackerid)) {
            $doTrackers->clientid = $moveto;
            $doTrackers->update();

            // Queue confirmation message
            $trackerName = $doTrackers->trackername;
            $doClients = OA_Dal::factoryDO('clients');
            if ($doClients->get($moveto)) {
                $advertiserName = $doClients->clientname;
            }
            $translation = new OX_Translation();
            $translated_message = $translation->translate ( $GLOBALS['strTrackerHasBeenMoved'],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,8 @@
 
 if (!empty($trackerid))
 {
+    OA_Permission::checkSessionToken();
+    
     if (!empty($moveto))
     {
         // Delete any campaign-tracker links
```
