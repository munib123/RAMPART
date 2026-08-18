# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 1744_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1744_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 10-53 of the vulnerable file.

+---------------------------------------------------------------------------+
*/

// Require the initialisation file
require_once '../../init-delivery.php';

// Required files
require_once MAX_PATH . '/lib/max/Delivery/adSelect.php';
require_once MAX_PATH . '/lib/max/Delivery/flash.php';
require_once MAX_PATH . '/lib/max/Delivery/javascript.php';

// No Caching
MAX_commonSetNoCacheHeaders();

//Register any script specific input variables
MAX_commonRegisterGlobalsArray(array('layerstyle'));
if (!isset($layerstyle) || empty($layerstyle)) {
    $layerstyle = 'geocities';
}

// Include layerstyle
if (file_exists(MAX_PATH . $conf['pluginPaths']['plugins'] . 'invocationTags/oxInvocationTags/layerstyles/' . $layerstyle . '/layerstyle.inc.php')) {
    include MAX_PATH . $conf['pluginPaths']['plugins'] . 'invocationTags/oxInvocationTags/layerstyles/' . $layerstyle . '/layerstyle.inc.php';
} else {
    // Don't generate output when plugin layerstyleisn't available,just send javascript comment on fail
    echo '// Cannot load required layerstyle file. Check if openXInvocationTags plugin is installed';
    exit(1);
}

//Register any script specific input variables
MAX_commonRegisterGlobalsArray(array('block', 'blockcampaign', 'exclude', 'mmm_fo', 'q'));

if (isset($context) && !is_array($context)) {
    $context = MAX_commonUnpackContext($context);
}
if (!is_array($context)) {
    $context = array();
}

$limitations = MAX_layerGetLimitations();

MAX_commonSendContentTypeHeader("application/x-javascript", $charset);
if ($limitations['compatible']) {
    $output = MAX_adSelect($what, $campaignid, $target, $source, $withtext, $charset, $context, $limitations['richmedia'], $GLOBALS['ct0'], $GLOBALS['loc'], $GLOBALS['referer']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,13 +27,13 @@
     $layerstyle = 'geocities';
 }
 
-// Include layerstyle
-if (file_exists(MAX_PATH . $conf['pluginPaths']['plugins'] . 'invocationTags/oxInvocationTags/layerstyles/' . $layerstyle . '/layerstyle.inc.php')) {
-    include MAX_PATH . $conf['pluginPaths']['plugins'] . 'invocationTags/oxInvocationTags/layerstyles/' . $layerstyle . '/layerstyle.inc.php';
-} else {
+$plugin = MAX_PATH.$conf['pluginPaths']['plugins'].'invocationTags/oxInvocationTags/layerstyles/'.$layerstyle.'/layerstyle.inc.php';
+
+if (!preg_match('/^[a-z0-9-]{1,64}$/Di', $layerstyle) || !@include($plugin)) {
     // Don't generate output when plugin layerstyleisn't available,just send javascript comment on fail
+    MAX_sendStatusCode(404);
     echo '// Cannot load required layerstyle file. Check if openXInvocationTags plugin is installed';
-    exit(1);
+    exit;
 }
 
 //Register any script specific input variables
```
