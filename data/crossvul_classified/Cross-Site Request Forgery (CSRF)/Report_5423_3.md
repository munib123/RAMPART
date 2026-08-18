# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5423_3
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_3`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1130-1170 of the vulnerable file.

        <option value='ad'$adSelected>{$GLOBALS['strLinkedBanners']}</option>
    </select>
    &nbsp;<input type='image' id='link_type_submit' src='" . OX::assetPath() . "/images/$phpAds_TextDirection/go_blue.gif' border='0'>
    $disabledHidden
</td>
</tr>
</table>
</form>";
    phpAds_ShowBreak();
    echo "
<br />";
}

function MAX_displayAcls($acls, $aParams)
{
    $tabindex =& $GLOBALS['tabindex'];
    $page = basename($_SERVER['SCRIPT_NAME']);
    $conf = $GLOBALS['_MAX']['CONF'];

    echo "<form action='{$page}' method='post'>";

    echo "<label><img src='" . OX::assetPath() . "/images/icon-acl-add.gif' align='absmiddle'>&nbsp;". $GLOBALS['strACLAdd'] .": &nbsp;";
    echo "<select name='type' accesskey='{$GLOBALS['keyAddNew']}' tabindex='".($tabindex++)."'>";

    $deliveryLimitations = OX_Component::getComponents('deliveryLimitations', null, false);
    foreach ($deliveryLimitations as $pluginName => $plugin) {
        if ($plugin->isAllowed($page)) {
            echo "<option value='{$pluginName}'>" . $plugin->getName() . "</option>";
        }
    }

    echo "</select></label>";
    echo "&nbsp;";
    echo "<input type='submit' class='flat' name='action[new]' value='" . $GLOBALS['strAdd'] . "'";

    phpAds_ShowBreak();
    echo "<br />";
    $aErrors = OX_AclCheckInputsFields($acls, $page);
    if (!empty($GLOBALS['action'])) {
        // We are part way through making changes, show a message
        //echo "<br>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1147,6 +1147,7 @@
     $conf = $GLOBALS['_MAX']['CONF'];
 
     echo "<form action='{$page}' method='post'>";
+    echo "<input type='hidden' name='token' value='".urlencode(phpAds_SessionGetToken())."' />";
 
     echo "<label><img src='" . OX::assetPath() . "/images/icon-acl-add.gif' align='absmiddle'>&nbsp;". $GLOBALS['strACLAdd'] .": &nbsp;";
     echo "<select name='type' accesskey='{$GLOBALS['keyAddNew']}' tabindex='".($tabindex++)."'>";
@@ -1689,11 +1690,14 @@
 function addTrackerPageTools($advertiserId, $trackerId, $aOtherAdvertisers)
 {
     if (OA_Permission::isAccount(OA_ACCOUNT_ADMIN) || OA_Permission::isAccount(OA_ACCOUNT_MANAGER)) {
+        $token = phpAds_SessionGetToken();
+
         //duplicate
-        addPageLinkTool($GLOBALS["strDuplicate"], MAX::constructUrl(MAX_URL_ADMIN, "tracker-modify.php?clientid=".$advertiserId."&trackerid=".$trackerId."&duplicate=true&returnurl=".urlencode(basename($_SERVER['SCRIPT_NAME']))), "iconTrackerDuplicate");
+        addPageLinkTool($GLOBALS["strDuplicate"], MAX::constructUrl(MAX_URL_ADMIN, "tracker-modify.php?token=".urlencode($token)."&clientid=".$advertiserId."&trackerid=".$trackerId."&duplicate=true&returnurl=".urlencode(basename($_SERVER['SCRIPT_NAME']))), "iconTrackerDuplicate");
 
         //move to
         $form  = "<form action='" . MAX::constructUrl(MAX_URL_ADMIN, 'tracker-modify.php') . "'>
+            <input type='hidden' name='token' value='".htmlspecialchars($token, ENT_QUOTES)."'>
             <input type='hidden' name='trackerid' value='$trackerId'
             <input type='hidden' name='clientid' value='$advertiserId'
             <input type='hidden' name='returnurl' value='tracker-edit.php'>
@@ -1706,7 +1710,7 @@
 
         //delete
         $deleteConfirm = phpAds_DelConfirm($GLOBALS['strConfirmDeleteTracker']);
-        addPageLinkTool($GLOBALS["strDelete"], MAX::constructUrl(MAX_URL_ADMIN, "tracker-delete.php?token=" . urlencode(phpAds_SessionGetToken()) . "&clientid=".$advertiserId."&trackerid=".$trackerId."&returnurl=advertiser-trackers.php"), "iconDelete", null, $deleteConfirm);
+        addPageLinkTool($GLOBALS["strDelete"], MAX::constructUrl(MAX_URL_ADMIN, "tracker-delete.php?token=".urlencode($token)."&clientid=".$advertiserId."&trackerid=".$trackerId."&returnurl=advertiser-trackers.php"), "iconDelete", null, $deleteConfirm);
         addPageShortcut($GLOBALS['strBackToTrackers'], MAX::constructUrl(MAX_URL_ADMIN, "advertiser-trackers.php?clientid=$advertiserId"), "iconBack");
     }
 }
@@ -1717,13 +1721,17 @@
     global $phpAds_TextDirection;
 
     if (!OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
-        addPageLinkTool($GLOBALS["strDuplicate"], MAX::constructUrl(MAX_URL_ADMIN, "campaign-modify.php?duplicate=1&clientid=$clientid&campaignid=$campaignid&returnurl=".urlencode(basename($_SERVER['SCRIPT_NAME']))), "iconCampaignDuplicate");
+
+        $token = phpAds_SessionGetToken();
+
+        addPageLinkTool($GLOBALS["strDuplicate"], MAX::constructUrl(MAX_URL_ADMIN, "campaign-modify.php?token=".urlencode($token)."&duplicate=1&clientid=$clientid&campaignid=$campaignid&returnurl=".urlencode(basename($_SERVER['SCRIPT_NAME']))), "iconCampaignDuplicate");
 
         if (OA_Permission::hasAccessToObject('campaigns', $campaignid, OA_Permission::OPERATION_MOVE)) {
             $form = "<form action='" . MAX::constructUrl(MAX_URL_ADMIN, 'campaign-modify.php') . "'>
+            <input type='hidden' name='token' value='".htmlspecialchars($token, ENT_QUOTES)."'>
             <input type='hidden' name='clientid' value='$clientid'>
             <input type='hidden' name='campaignid' value='$campaignid'>
-            <input type='hidden' name='returnurl' value='".htmlspecialchars(basename($_SERVER['SCRIPT_NAME']))."'>
+            <input type='hidden' name='returnurl' value='".htmlspecialchars(basename($_SERVER['SCRIPT_NAME'], ENT_QUOTES))."'>
             <select name='newclientid'>";
                 $aOtherAdvertisers = _multiSort($aOtherAdvertisers,'name','advertiser_id');
                 foreach ($aOtherAdvertisers as $aOtherAdvertiser) {
@@ -1740,7 +1748,7 @@
         }
 
         $deleteConfirm = phpAds_DelConfirm($GLOBALS['strConfirmDeleteCampaign']);
-        addPageLinkTool($GLOBALS["strDelete"], MAX::constructUrl(MAX_URL_ADMIN, "campaign-delete.php?token=" . urlencode(phpAds_SessionGetToken()) . "&clientid=$clientid&campaignid=$campaignid&returnurl=advertiser-campaigns.php"), "iconDelete", null, $deleteConfirm);
+        addPageLinkTool($GLOBALS["strDelete"], MAX::constructUrl(MAX_URL_ADMIN, "campaign-delete.php?token=".urlencode($token)."&clientid=$clientid&campaignid=$campaignid&returnurl=advertiser-campaigns.php"), "iconDelete", null, $deleteConfirm);
     }
 
     //shortcuts
@@ -1761,16 +1769,20 @@
 
 function addBannerPageTools($advertiserId, $campaignId, $bannerId, $aOtherCampaigns, $aOtherBanners, $aEntities)
 {
+    global $phpAds_TextDirection;
+
     if (empty($bannerId)) {
         return;
     }
 
-    global $phpAds_TextDirection;
+    $token = phpAds_SessionGetToken();
+
     //duplicate
-    addPageLinkTool($GLOBALS["strDuplicate"], MAX::constructUrl(MAX_URL_ADMIN, "banner-modify.php?duplicate=true&clientid=$advertiserId&campaignid=$campaignId&bannerid=$bannerId&returnurl=".urlencode(basename($_SERVER['SCRIPT_NAME']))), "iconBannerDuplicate");
+    addPageLinkTool($GLOBALS["strDuplicate"], MAX::constructUrl(MAX_URL_ADMIN, "banner-modify.php?token=".urlencode($token)."&duplicate=true&clientid=$advertiserId&campaignid=$campaignId&bannerid=$bannerId&returnurl=".urlencode(basename($_SERVER['SCRIPT_NAME']))), "iconBannerDuplicate");
 
     //move to
     $form = "<form action='" . MAX::constructUrl(MAX_URL_ADMIN, 'banner-modify.php') . "'>
+    <input type='hidden' name='token' value='".htmlspecialchars($token, ENT_QUOTES)."'>
     <input type='hidden' name='clientid' value='$advertiserId'>
     <input type='hidden' name='campaignid' value='$campaignId'>
     <input type='hidden' name='bannerid' value='$bannerId'>
@@ -1795,6 +1807,7 @@
     //apply to
     if (basename($_SERVER['SCRIPT_NAME']) == 'banner-acl.php') {
         $form = "<form action='" . MAX::constructUrl(MAX_URL_ADMIN, 'banner-modify.php') . "'>
+        <input type='hidden' name='token' value='".htmlspecialchars($token, ENT_QUOTES)."'>
         <input type='hidden' name='clientid' value='$advertiserId'>
         <input type='hidden' name='campaignid' value='$campaignId'>
         <input type='hidden' name='bannerid' value='$bannerId'>
@@ -1815,7 +1828,7 @@
     //delete
     if (!OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
         $deleteConfirm = phpAds_DelConfirm($GLOBALS['strConfirmDeleteBanner']);
-        addPageLinkTool($GLOBALS["strDelete"], MAX::constructUrl(MAX_URL_ADMIN, "banner-delete.php?token=" . urlencode(phpAds_SessionGetToken()) . "&clientid=$advertiserId&campaignid=$campaignId&bannerid=$bannerId&returnurl=campaign-banners.php"), "iconDelete", null, $deleteConfirm);
+        addPageLinkTool($GLOBALS["strDelete"], MAX::constructUrl(MAX_URL_ADMIN, "banner-delete.php?token=".urlencode($token)."&clientid=$advertiserId&campaignid=$campaignId&bannerid=$bannerId&returnurl=campaign-banners.php"), "iconDelete", null, $deleteConfirm);
     }
 
     /* Shortcuts */
@@ -1840,6 +1853,9 @@
 function addZonePageTools($affiliateid, $zoneid, $aOtherPublishers, $aEntities)
 {
     global $phpAds_TextDirection;
+
+    $token = phpAds_SessionGetToken();
+
     //duplicate
     if (OA_Permission::isAccount(OA_ACCOUNT_ADMIN)
         || OA_Permission::isAccount(OA_ACCOUNT_MANAGER)
@@ -1851,6 +1867,7 @@
     if (OA_Permission::isAccount(OA_ACCOUNT_ADMIN)
         || OA_Permission::isAccount(OA_ACCOUNT_MANAGER)) {
         $form = "<form action='" . MAX::constructUrl(MAX_URL_ADMIN, 'zone-modify.php') . "'>
+        <input type='hidden' name='token' value='".htmlspecialchars($token, ENT_QUOTES)."'>
... (diff truncated)
```
