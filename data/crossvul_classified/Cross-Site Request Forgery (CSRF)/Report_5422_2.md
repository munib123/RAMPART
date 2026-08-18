# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5422_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5422_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 22-68 of the vulnerable file.


// Security check
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

/*-------------------------------------------------------*/
/* Process submitted form                                */
/*-------------------------------------------------------*/

if (isset($submitbutton)) {
    if (isset($bannerid) && $bannerid != '') {
        // Update banner
        $doBanners = OA_Dal::factoryDO('banners');
        $doBanners->get($bannerid);
        $doBanners->prepend = $prepend;
        $doBanners->append  = $append;
        $doBanners->update();

        // Queue confirmation message
        $translation = new OX_Translation();
        $translated_message = $translation->translate($GLOBALS['strBannerAdvancedHasBeenUpdated'], array(
            MAX::constructURL(MAX_URL_ADMIN, 'banner-edit.php?clientid=' .  $clientid . '&campaignid=' . $campaignid . '&bannerid=' . $bannerid),
            htmlspecialchars($doBanners->description)
        ));
        OA_Admin_UI::queueMessage($translated_message, 'local', 'confirm', 0);
    }
    header ("Location: banner-advanced.php?clientid=".$clientid."&campaignid=".$campaignid."&bannerid=".$bannerid);
}

/*-------------------------------------------------------*/
/* HTML framework                                        */
/*-------------------------------------------------------*/

// Initialise some parameters
$pageName = basename($_SERVER['SCRIPT_NAME']);
$tabindex = 1;
$agencyId = OA_Permission::getAgencyId();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,23 +39,26 @@
 /*-------------------------------------------------------*/
 
 if (isset($submitbutton)) {
-    if (isset($bannerid) && $bannerid != '') {
-        // Update banner
-        $doBanners = OA_Dal::factoryDO('banners');
-        $doBanners->get($bannerid);
-        $doBanners->prepend = $prepend;
-        $doBanners->append  = $append;
-        $doBanners->update();
+    OA_Permission::checkSessionToken();
 
-        // Queue confirmation message
-        $translation = new OX_Translation();
-        $translated_message = $translation->translate($GLOBALS['strBannerAdvancedHasBeenUpdated'], array(
-            MAX::constructURL(MAX_URL_ADMIN, 'banner-edit.php?clientid=' .  $clientid . '&campaignid=' . $campaignid . '&bannerid=' . $bannerid),
-            htmlspecialchars($doBanners->description)
-        ));
-        OA_Admin_UI::queueMessage($translated_message, 'local', 'confirm', 0);
-    }
+    // Update banner
+    $doBanners = OA_Dal::factoryDO('banners');
+    $doBanners->get($bannerid);
+    $doBanners->prepend = $prepend;
+    $doBanners->append  = $append;
+    $doBanners->update();
+
+    // Queue confirmation message
+    $translation = new OX_Translation();
+    $translated_message = $translation->translate($GLOBALS['strBannerAdvancedHasBeenUpdated'], array(
+        MAX::constructURL(MAX_URL_ADMIN, 'banner-edit.php?clientid=' .  $clientid . '&campaignid=' . $campaignid . '&bannerid=' . $bannerid),
+        htmlspecialchars($doBanners->description)
+    ));
+
+    OA_Admin_UI::queueMessage($translated_message, 'local', 'confirm', 0);
+
     header ("Location: banner-advanced.php?clientid=".$clientid."&campaignid=".$campaignid."&bannerid=".$bannerid);
+    exit;
 }
 
 /*-------------------------------------------------------*/
```
