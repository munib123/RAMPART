# CrossVul Fix Pair: 7PK in php
**Pair ID:** 5470_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5470_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```php
Lines 11-51 of the vulnerable file.

*/

// Require the initialisation file
require_once '../../init-delivery.php';

// Required files
require_once MAX_PATH . '/lib/max/Delivery/adSelect.php';
require_once MAX_PATH . '/lib/max/Delivery/javascript.php';

MAX_commonSetNoCacheHeaders();

/*-------------------------------------------------------*/
/* Register input variables                              */
/*-------------------------------------------------------*/

MAX_commonRegisterGlobalsArray(array('zones' ,'source', 'block', 'blockcampaign', 'exclude', 'q', 'prefix'));

/*-------------------------------------------------------*/
/* Main code                                             */
/*-------------------------------------------------------*/

// Derive the source parameter
$source = MAX_commonDeriveSource($source);

$spc_output = array();

if(!empty($zones)) {
    $zones = explode('|', $zones);
    foreach ($zones as $id => $thisZoneid) {
        $zonename = $prefix.$id;

        // Clear deiveryData between iterations
        unset($GLOBALS['_MAX']['deliveryData']);

        $what = 'zone:'.$thisZoneid;

        // Get the banner
        $output = MAX_adSelect($what, $clientid, $target, $source, $withtext, $charset, $context, true, $ct0, $GLOBALS['loc'], $GLOBALS['referer']);

        $spc_output[$zonename] = array(
            'html' => $output['html'],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,12 @@
 /*-------------------------------------------------------*/
 /* Main code                                             */
 /*-------------------------------------------------------*/
+
+// Protect from Reflected File Download attacks
+if (preg_match('/[^a-zA-Z0-9_-]/', $prefix)) {
+    MAX_sendStatusCode(400);
+    exit;
+}
 
 // Derive the source parameter
 $source = MAX_commonDeriveSource($source);
```
