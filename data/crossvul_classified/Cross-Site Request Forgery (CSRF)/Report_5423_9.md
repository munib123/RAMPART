# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5423_9
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_9`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 17-57 of the vulnerable file.

require_once MAX_PATH . '/lib/OA/Dal.php';
require_once MAX_PATH . '/www/admin/config.php';

// Register input variables
phpAds_registerGlobal('newaffiliateid', 'returnurl', 'duplicate');


// Security check
OA_Permission::enforceAccount(OA_ACCOUNT_MANAGER);
OA_Permission::enforceAccessToObject('channel', $channelid);

$affiliateid    = (int) $affiliateid;
$channelid      = (int) $channelid;

if (empty($returnurl)) {
    $returnurl = 'channel-edit.php';
}

// Security check
if (isset($channelid) && $channelid != '') {
    if (isset($duplicate) && $duplicate == 'true') {

        //get channel old channel name
        $doChannel = OA_Dal::factoryDO('channel');
        if ($doChannel->get($channelid)) {
            $oldName = $doChannel->name;
        }
        // Duplicate the channel
        $newChannelId = OA_Dal::staticDuplicate('channel', $channelid);

        //get new name
        $doChannel = OA_Dal::factoryDO('channel');
        if ($doChannel->get($newChannelId)) {
            $newName = $doChannel->name;
        }
        // Queue confirmation message
        $translation = new OX_Translation();
        $oldChannelParams = (!$affiliateid)
            ? "channelid=$channelid"
            :   "affiliateid=$affiliateid&channelid=$channelid";

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,8 @@
 
 // Security check
 if (isset($channelid) && $channelid != '') {
+    OA_Permission::checkSessionToken();
+
     if (isset($duplicate) && $duplicate == 'true') {
 
         //get channel old channel name
```
