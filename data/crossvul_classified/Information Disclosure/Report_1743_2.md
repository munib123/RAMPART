# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1743_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1743_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 6-47 of the vulnerable file.

| http://www.revive-adserver.com                                            |
|                                                                           |
| Copyright: See the COPYRIGHT.txt file.                                    |
| License: GPLv2 or later, see the LICENSE.txt file.                        |
+---------------------------------------------------------------------------+
*/

// Require the initialisation file
require_once '../../init.php';

// Required files
require_once MAX_PATH . '/www/admin/lib-maintenance-priority.inc.php';
require_once MAX_PATH . '/lib/max/Delivery/common.php';
require_once MAX_PATH . '/lib/max/other/common.php';
require_once MAX_PATH . '/www/admin/config.php';

require_once MAX_PATH . '/lib/OA/Admin/DaySpan.php';
require_once MAX_PATH . '/lib/OA/Admin/Statistics/Factory.php';
require_once MAX_PATH . '/lib/pear/Date.php';

// No cache
MAX_commonSetNoCacheHeaders();

// The URL for stats pages may include values for "period_preset",
// "period_start" and "period_end". However, the user may have
// bookmarked or emailed a statsistics URL, and so the page may
// be viewed on a day that is NOT the day the URL was created.
// As a result, the "period_preset" value may no longer match
// the dates. So, to prevent confusion, re-set the "period_preset"
// value to the range that matches the date, if possible - otherwise
// use the "Specific Dates" value. The exception, of course, is
// "".
$periodPreset = MAX_getValue('period_preset', 'today');
if ($periodPreset == 'all_stats') {
    unset($_REQUEST['period_start']);
    unset($session['prefs']['GLOBALS']['period_start']);
    unset($_REQUEST['period_end']);
    unset($session['prefs']['GLOBALS']['period_end']);
    $_REQUEST['period_preset'] = $periodPreset;
    $session['prefs']['GLOBALS']['period_preset'] = $periodPreset;
} else {
    $period_start = htmlspecialchars(MAX_getStoredValue('period_start', date('Y-m-d')));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,8 +23,6 @@
 require_once MAX_PATH . '/lib/OA/Admin/Statistics/Factory.php';
 require_once MAX_PATH . '/lib/pear/Date.php';
 
-// No cache
-MAX_commonSetNoCacheHeaders();
 
 // The URL for stats pages may include values for "period_preset",
 // "period_start" and "period_end". However, the user may have
```
