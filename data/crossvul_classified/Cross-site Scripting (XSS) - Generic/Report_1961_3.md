# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1961_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1961_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 24-65 of the vulnerable file.

require_once MAX_PATH . '/lib/OA/Dal.php';
require_once MAX_PATH . '/lib/OA/ServiceLocator.php';

require_once LIB_PATH . '/Dal/Maintenance/Statistics/Factory.php';
require_once LIB_PATH . '/OperationInterval.php';
require_once OX_PATH . '/lib/pear/Date.php';

$clientId      = MAX_getValue('clientid');
$campaignId    = MAX_getValue('campaignid');
$bannerId      = MAX_getValue('bannerid');
$affiliateId   = MAX_getValue('affiliteid');
$zoneId        = MAX_getValue('zoneid');
$period_preset = MAX_getValue('period_preset');
$period_start  = MAX_getValue('period_start');
$period_end    = MAX_getValue('period_end');
$day           = MAX_getValue('day');
$howLong       = MAX_getValue('howLong');
$hour          = MAX_getValue('hour');
$returnurl     = MAX_getValue('returnurl');
$statusIds     = MAX_getValue('statusIds');
$pageID        = MAX_getValue('pageID');
$setPerPage    = MAX_getValue('setPerPage');

$aParams = array();

$aParams['clientid']   = $clientId;
$aParams['campaignid'] = $campaignId;
$aParams['bannerid']   = $bannerId;

// Security check
OA_Permission::enforceAccount(OA_ACCOUNT_MANAGER);

// CVE-2013-5954 - see OA_Permission::checkSessionToken() method for details
OA_Permission::checkSessionToken();

if (!empty($day)) {
    // Reset period
    $period_preset = '';
    // Always refresh howLong and hour
    $howLong = MAX_getValue('howLong', 'd');
    $hour    = MAX_getValue('hour');
} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,8 +41,8 @@
 $hour          = MAX_getValue('hour');
 $returnurl     = MAX_getValue('returnurl');
 $statusIds     = MAX_getValue('statusIds');
-$pageID        = MAX_getValue('pageID');
-$setPerPage    = MAX_getValue('setPerPage');
+$pageID        = (int) MAX_getValue('pageID');
+$setPerPage    = (int) MAX_getValue('setPerPage', 15);
 
 $aParams = array();
 
```
