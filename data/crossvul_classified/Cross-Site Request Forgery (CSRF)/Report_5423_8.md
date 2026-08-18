# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5423_8
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_8`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 42-82 of the vulnerable file.

	/*-------------------------------------------------------*/
	$session['prefs']['inventory_entities'][OA_Permission::getEntityId()]['affiliateid'] = $affiliateid;
	phpAds_SessionDataStore();

    $aEntities = array('agencyid' => $agencyId, 'affiliateid' => $affiliateid, 'channelid' => $channelid);
    $aOtherChannels = Admin_DA::getChannels(array('publisher_id' => $affiliateid));
} else {
    $aEntities = array('agencyid' => $agencyId, 'channelid' => $channelid);
    $aOtherChannels = Admin_DA::getChannels(array('agency_id' => $agencyId, 'channel_type' => 'agency'));
}

/*-------------------------------------------------------*/
/* Process submitted form                                */
/*-------------------------------------------------------*/

if (!empty($action)) {
    if (empty($acl)) $acl = array();
    $acl = MAX_AclAdjust($acl, $action);
}
elseif (!empty($submit)) {
    $acl = (isset($acl)) ? $acl : array();
    // Only save when inputs are valid
    if (OX_AclCheckInputsFields($acl, $pageName) === true) {
        if (MAX_AclSave($acl, $aEntities)) {

            // Queue confirmation message
            $doChannel = OA_Dal::factoryDO('channel');
            $doChannel->get($channelid);

            $translation = new OX_Translation ();
            $translated_message = $translation->translate ( $GLOBALS['strChannelAclHasBeenUpdated'], array(
                MAX::constructURL(MAX_URL_ADMIN, "channel-edit.php?" . (!empty($affiliateid) ? "affiliateid={$affiliateid}&" : "") . "channelid={$channelid}"),
                htmlspecialchars($doChannel->name)
            ));
            OA_Admin_UI::queueMessage($translated_message, 'local', 'confirm', 0);

            // Redirect
            if (!empty($affiliateid)) {
                header("Location: channel-acl.php?affiliateid={$affiliateid}&channelid={$channelid}");
            } else {
                header("Location: channel-acl.php?channelid={$channelid}");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,6 +59,8 @@
     $acl = MAX_AclAdjust($acl, $action);
 }
 elseif (!empty($submit)) {
+    OA_Permission::checkSessionToken();
+
     $acl = (isset($acl)) ? $acl : array();
     // Only save when inputs are valid
     if (OX_AclCheckInputsFields($acl, $pageName) === true) {
```
