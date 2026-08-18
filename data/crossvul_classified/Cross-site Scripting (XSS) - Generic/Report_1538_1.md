# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 1538_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1538_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 16-56 of the vulnerable file.

    <script src="shared/js/idletimer.js"></script>
    <script src="shared/js/dump.js"></script>
    <script defer src="shared/js/nfc_utils.js"></script>
    <script defer src="shared/js/gesture_detector.js"></script>
    <script defer src="shared/js/settings_listener.js"></script>
    <script defer src="shared/js/custom_dialog.js"></script>
    <script defer src="shared/js/notification_helper.js"></script>
    <script defer src="shared/js/async_storage.js"></script>
    <script defer src="shared/js/mobile_operator.js"></script>
    <script defer src="shared/js/manifest_helper.js"></script>
    <!-- We need this before we can show the boot animation -->
    <script src="shared/js/settings_helper.js"></script>
    <script defer src="shared/js/icc_helper.js"></script>
    <script defer src="shared/js/mime_mapper.js"></script>
    <script defer src="shared/js/settings_url.js"></script>
    <script defer src="shared/js/advanced_timer.js"></script>
    <script defer src="shared/js/lazy_loader.js"></script>
    <script defer src="shared/js/screen_layout.js"></script>
    <script defer src="shared/js/iac_handler.js"></script>
    <script defer src="shared/js/apn_helper.js"></script>
    <script defer src="shared/js/utilities.js"></script>
    <script defer src="js/touch_forwarder.js"></script>
    <script defer src="shared/js/version_helper.js"></script>
    <script defer src="shared/js/font_size_utils.js"></script>
    <script defer src="js/migrators/settings_migrator.js"></script>
    <!-- XXX can be removed while gecko support navigator.mozHour12 API -->
    <script defer src="shared/js/date_time_helper.js"></script>

    <script defer src="js/service.js"></script>
    <script defer src="js/base_ui.js"></script>
    <script defer src="js/places.js"></script>

    <script defer src="js/orientation_manager.js"></script>
    <!--
    <script defer src="shared/js/input_mgmt/input_app_list.js"></script>
    <script defer src="shared/js/keyboard_helper.js"></script>
    <script defer src="shared/js/template.js"></script>
    -->

    <!-- Battery Overlay -->
    <link rel="stylesheet" type="text/css" href="style/battery_overlay/battery_overlay.css">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,6 +33,7 @@
     <script defer src="shared/js/screen_layout.js"></script>
     <script defer src="shared/js/iac_handler.js"></script>
     <script defer src="shared/js/apn_helper.js"></script>
+    <script defer src="shared/js/tagged.js"></script>
     <script defer src="shared/js/utilities.js"></script>
     <script defer src="js/touch_forwarder.js"></script>
     <script defer src="shared/js/version_helper.js"></script>
```
