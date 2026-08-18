# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5424_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5424_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 41-91 of the vulnerable file.


if (!empty($day)) {
    // Reset period
    $period_preset = '';
    // Always refresh howLong and hour
    $howLong = MAX_getValue('howLong', 'd');
    $hour    = MAX_getValue('hour');
} else {
    $period_preset  = MAX_getStoredValue('period_preset', 'today');
    $period_start   = MAX_getStoredValue('period_start', date('Y-m-d'));
    $period_end     = MAX_getStoredValue('period_end', date('Y-m-d'));
}

if (is_numeric($hour) && $hour < 10 && strlen($hour) != 2) {
    $hour = '0' . $hour;
}

$expand         = MAX_getValue('expand', '');
$collapse       = MAX_getValue('collapse');

$clientId       = MAX_getValue('clientid');
$campaignId     = MAX_getValue('campaignid');
$bannerId       = MAX_getValue('bannerid');

$affiliateId    = MAX_getValue('affiliateid');
$zoneId         = MAX_getValue('zoneid');

if (OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
    $clientId = $clientid = OA_Permission::getEntityId();
} elseif (OA_Permission::isAccount(OA_ACCOUNT_TRAFFICKER)) {
    $affiliateId = $affiliateid = OA_Permission::getEntityId();
}

// Build $addUrl variable which will be added to any required link on this page, eg: expand, collapse, editStatuses
$entityIds = array(
    'entity'      => 'conversions',
    'clientid'    => $clientid,
    'campaignid'  => $campaignId,
    'bannerid'    => $bannerId,
    'affiliateid' => $affiliateId,
    'zoneid'      => $zoneId,
    'setPerPage'  => $setPerPage,
    'pageID'      => $pageID
);
$addUrl = "entity=conversions&clientid=$clientId&campaignid=$campaignId&bannerid=$bannerId&affiliateid=$affiliateId&zoneid=$zoneId&setPerPage=$setPerPage&pageID=$pageID";

if (!empty($day)) {
    $entityIds += array(
        'day' => $day,
        'hour' => $hour,
        'howLong' => $howLong
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,31 +58,34 @@
 $expand         = MAX_getValue('expand', '');
 $collapse       = MAX_getValue('collapse');
 
-$clientId       = MAX_getValue('clientid');
-$campaignId     = MAX_getValue('campaignid');
-$bannerId       = MAX_getValue('bannerid');
-
-$affiliateId    = MAX_getValue('affiliateid');
-$zoneId         = MAX_getValue('zoneid');
-
-if (OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
-    $clientId = $clientid = OA_Permission::getEntityId();
-} elseif (OA_Permission::isAccount(OA_ACCOUNT_TRAFFICKER)) {
-    $affiliateId = $affiliateid = OA_Permission::getEntityId();
+if ($clientid) {
+    OA_Permission::enforceAccessToObject('clients', $clientid);
+}
+if ($campaignid) {
+    OA_Permission::enforceAccessToObject('campaigns', $campaignid);
+}
+if ($bannerid) {
+    OA_Permission::enforceAccessToObject('banners', $bannerid);
+}
+if ($affiliateid) {
+    OA_Permission::enforceAccessToObject('affiliates', $clientid);
+}
+if ($zoneid) {
+    OA_Permission::enforceAccessToObject('zones', $zoneid);
 }
 
 // Build $addUrl variable which will be added to any required link on this page, eg: expand, collapse, editStatuses
 $entityIds = array(
     'entity'      => 'conversions',
     'clientid'    => $clientid,
-    'campaignid'  => $campaignId,
-    'bannerid'    => $bannerId,
-    'affiliateid' => $affiliateId,
-    'zoneid'      => $zoneId,
+    'campaignid'  => $campaignid,
+    'bannerid'    => $bannerid,
+    'affiliateid' => $affiliateid,
+    'zoneid'      => $zoneid,
     'setPerPage'  => $setPerPage,
     'pageID'      => $pageID
 );
-$addUrl = "entity=conversions&clientid=$clientId&campaignid=$campaignId&bannerid=$bannerId&affiliateid=$affiliateId&zoneid=$zoneId&setPerPage=$setPerPage&pageID=$pageID";
+$addUrl = "entity=conversions&clientid=$clientid&campaignid=$campaignid&bannerid=$bannerid&affiliateid=$affiliateid&zoneid=$zoneid&setPerPage=$setPerPage&pageID=$pageID";
 
 if (!empty($day)) {
     $entityIds += array(
@@ -90,14 +93,14 @@
         'hour' => $hour,
         'howLong' => $howLong
     );
-    $addUrl .= "&day={$day}&hour={$hour}&howLong={$howLong}";
+    $addUrl .= "&day=".urlencode($day)."&hour=".urlencode($hour)."&howLong=".urlencode($howLong);
 } else {
     $entityIds += array(
         'period_preset' => $period_preset,
         'period_start' => $period_start,
         'period_end' => $period_end,
     );
-    $addUrl .= "&period_preset={$period_preset}&period_start={$period_start}&period_end={$period_end}";
+    $addUrl .= "&period_preset=".urlencode($period_preset)."&period_start=".urlencode($period_start)."&period_end=".urlencode($period_end);
 }
 // Adjust which nodes are opened closed...
 MAX_adjustNodes($aNodes, $expand, $collapse);
@@ -178,11 +181,11 @@
 
 $hiddenValues = array(
     'entity'   => 'conversions',
-    'clientid' => $clientId,
-    'campaignid' => $campaignId,
-    'bannerid' => $bannerId,
-    'affiliateid' => $affiliateId,
-    'zoneid' => $zoneId,
+    'clientid' => $clientid,
+    'campaignid' => $campaignid,
+    'bannerid' => $bannerid,
+    'affiliateid' => $affiliateid,
+    'zoneid' => $zoneid,
 );
 if(!empty($period_preset)) {
     MAX_displayDateSelectionForm($period_preset, $period_start, $period_end, $pageName, $tabindex, $hiddenValues);
@@ -199,15 +202,15 @@
 $aParams = array();
 $aParams['agency_id'] = OA_Permission::getAgencyId();
 
-$aParams['clientid']    = $clientId;
-$aParams['campaignid']  = $campaignId;
-$aParams['bannerid']    = $bannerId;
+$aParams['clientid']    = $clientid;
+$aParams['campaignid']  = $campaignid;
+$aParams['bannerid']    = $bannerid;
 $aZonesIds = null; // Admin_DA class expects null if no zones to be used
-if (empty($zoneId) && !empty($affiliateId)) {
-    $aZonesIds = Admin_DA::fromCache('getZonesIdsByAffiliateId', $affiliateId);
-}
-if(!empty($zoneId)) {
-    $aZonesIds = array($zoneId);
+if (empty($zoneid) && !empty($affiliateid)) {
+    $aZonesIds = Admin_DA::fromCache('getZonesIdsByAffiliateId', $affiliateid);
+}
+if(!empty($zoneid)) {
+    $aZonesIds = array($zoneid);
 }
 $aParams['zonesIds'] = $aZonesIds;
 
@@ -251,23 +254,23 @@
 
     if($editStatuses) {
         echo "<form id='connections-modify' action='connections-modify.php' name='connectionsmodify' id='connectionsmodify' method='POST'>"."\n";
-        echo "<input type='hidden' name='clientid' value='$clientId'>"."\n";
-        echo "<input type='hidden' name='campaignid' value='$campaignId'>"."\n";
-        echo "<input type='hidden' name='bannerid' value='$bannerId'>"."\n";
-        echo "<input type='hidden' name='affiliateid' value='$affiliateId'>"."\n";
-        echo "<input type='hidden' name='zoneid' value='$zoneId'>"."\n";
-        echo "<input type='hidden' name='day' value='$day'>"."\n";
-        echo "<input type='hidden' name='hour' value='$hour'>"."\n";
-        echo "<input type='hidden' name='howLong' value='$howLong'>"."\n";
-        echo "<input type='hidden' name='period_preset' value='$period_preset'>"."\n";
+        echo "<input type='hidden' name='clientid' value='$clientid'>"."\n";
+        echo "<input type='hidden' name='campaignid' value='$campaignid'>"."\n";
+        echo "<input type='hidden' name='bannerid' value='$bannerid'>"."\n";
+        echo "<input type='hidden' name='affiliateid' value='$affiliateid'>"."\n";
+        echo "<input type='hidden' name='zoneid' value='$zoneid'>"."\n";
+        echo "<input type='hidden' name='day' value='".htmlspecialchars($day, ENT_QUOTES)."'>"."\n";
+        echo "<input type='hidden' name='hour' value='".htmlspecialchars($hour, ENT_QUOTES)."'>"."\n";
+        echo "<input type='hidden' name='howLong' value='".htmlspecialchars($howLong, ENT_QUOTES)."'>"."\n";
+        echo "<input type='hidden' name='period_preset' value='".htmlspecialchars($period_preset, ENT_QUOTES)."'>"."\n";
         if ($period_preset == 'specific') {
-            echo "<input type='hidden' name='period_start' value='$period_start'>"."\n";
-            echo "<input type='hidden' name='period_end' value='$period_end'>"."\n";
+            echo "<input type='hidden' name='period_start' value='".htmlspecialchars($period_start, ENT_QUOTES)."'>"."\n";
+            echo "<input type='hidden' name='period_end' value='".htmlspecialchars($period_end, ENT_QUOTES)."'>"."\n";
         }
         echo "<input type='hidden' name='returnurl' value='stats.php'>"."\n";
         echo "<input type='hidden' name='entity' value='conversions'>"."\n";
-        echo "<input type='hidden' name='setPerPage' value='$setPerPage'>"."\n";
-        echo "<input type='hidden' name='pageID' value='$pageID'>"."\n";
+        echo "<input type='hidden' name='setPerPage' value='".htmlspecialchars($setPerPage, ENT_QUOTES)."'>"."\n";
+        echo "<input type='hidden' name='pageID' value='".htmlspecialchars($pageID, ENT_QUOTES)."'>"."\n";
     }
 
     echo "
@@ -331,9 +334,9 @@
         <tr height='25'$bgcolor>
             <td>";
             if ($conversionExpanded) {
-                echo "&nbsp;<a href='$pageName?collapse=a$conversionId&$addUrl'><img src='" . OX::assetPath() . "/images/triangle-d.gif' align='absmiddle' border='0'></a>&nbsp;";
+                echo "&nbsp;<a href='".htmlspecialchars("$pageName?collapse=a$conversionId&$addUrl", ENT_QUOTES)."'><img src='" . OX::assetPath() . "/images/triangle-d.gif' align='absmiddle' border='0'></a>&nbsp;";
             } else {
-                echo "&nbsp;<a href='$pageName?expand=a$conversionId&$addUrl'><img src='" . OX::assetPath() . "/images/$phpAds_TextDirection/triangle-l.gif' align='absmiddle' border='0'></a>&nbsp;";
+                echo "&nbsp;<a href='".htmlspecialchars("$pageName?expand=a$conversionId&$addUrl", ENT_QUOTES)."'><img src='" . OX::assetPath() . "/images/$phpAds_TextDirection/triangle-l.gif' align='absmiddle' border='0'></a>&nbsp;";
             }
 
             $aConversionStatuses = array(
@@ -444,7 +447,7 @@
             <td colspan='4' align='$phpAds_TextAlignLeft' nowrap>";
... (diff truncated)
```
