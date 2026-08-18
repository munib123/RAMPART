# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1961_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1961_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 19-60 of the vulnerable file.

require_once MAX_PATH . '/lib/max/other/common.php';
require_once MAX_PATH . '/lib/max/Admin_DA.php';
require_once MAX_PATH . '/lib/max/other/html.php';
require_once MAX_PATH . '/lib/max/other/stats.php';
require_once 'Pager/Pager.php';
require_once MAX_PATH . '/lib/pear/Date.php';

// Security check
OA_Permission::enforceAccount(OA_ACCOUNT_MANAGER, OA_ACCOUNT_ADVERTISER, OA_ACCOUNT_TRAFFICKER);

// Get input variables
$pref = $GLOBALS['_MAX']['PREF'];
$hideinactive   = MAX_getStoredValue('hideinactive', ($pref['ui_hide_inactive'] == true), null, true);
$listorder      = MAX_getStoredValue('listorder', 'date_time');
$orderdirection = MAX_getStoredValue('orderdirection', 'up');
$aNodes         = MAX_getStoredArray('nodes', array());
$editStatuses   = MAX_getStoredValue('editStatuses', false, null, true);
$day            = MAX_getStoredValue('day', null, 'stats-conversions.php');
$howLong        = MAX_getStoredValue('howLong', 'd');
$hour           = MAX_getStoredValue('hour', null, 'stats-conversions.php', true);
$setPerPage     = MAX_getStoredValue('setPerPage', 15);
$pageID         = MAX_getStoredValue('pageID', 1);

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

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,8 +36,8 @@
 $day            = MAX_getStoredValue('day', null, 'stats-conversions.php');
 $howLong        = MAX_getStoredValue('howLong', 'd');
 $hour           = MAX_getStoredValue('hour', null, 'stats-conversions.php', true);
-$setPerPage     = MAX_getStoredValue('setPerPage', 15);
-$pageID         = MAX_getStoredValue('pageID', 1);
+$setPerPage     = (int) MAX_getStoredValue('setPerPage', 15);
+$pageID         = (int) MAX_getStoredValue('pageID', 1);
 
 if (!empty($day)) {
     // Reset period
@@ -225,7 +225,7 @@
 
 
 $aParams['totalItems'] = count($aConversions);
-$aParams['perPage'] = MAX_getStoredValue('setPerPage', 15);
+$aParams['perPage'] = (int) MAX_getStoredValue('setPerPage', 15);
 
 if (!isset($pageID) || $pageID == 1) {
     $aParams['startRecord'] = 0;
@@ -237,9 +237,6 @@
 
 $aConversions = Admin_DA::fromCache('getConversions', $aParams + $aDates);
 
-
-$aParams['perPage'] = MAX_getStoredValue('setPerPage', 15);
-//$aParams['startRecord'] = $_REQUEST['page'];
 
 $pager = & Pager::factory($aParams);
 $per_page = $pager->_perPage;
```
