# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1961_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1961_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 71-112 of the vulnerable file.

}


// Paging related input variables
$listorder      = htmlspecialchars(MAX_getStoredValue('listorder', 'updated'));
$oAudit = &OA_Dal::factoryDO('audit');
$aAuditColumns = $oAudit->table();
$aColumnNamesFound = array_keys($aAuditColumns, $listorder);
if (empty($aColumnNamesFound)) {
    // Invalid column name to order by, set to default
    $listorder = 'updated';
}
$orderdirection = htmlspecialchars(MAX_getStoredValue('orderdirection', 'up'));
if (!($orderdirection == 'up' || $orderdirection == 'down')) {
    if (stristr($orderdirection, 'down')) {
        $orderdirection = 'down';
    } else {
        $orderdirection = 'up';
    }
}
$setPerPage     = MAX_getStoredValue('setPerPage',      10);
$pageID         = MAX_getStoredValue('pageID',          1);

// Setup date selector
$aPeriod = array(
    'period_preset'     => $periodPreset,
    'period_start'      => $startDate,
    'period_end'        => $endDate
);
$daySpan = new OA_Admin_UI_Audit_DaySpanField('period');
$daySpan->setValueFromArray($aPeriod);
$daySpan->enableAutoSubmit();

// Initialize parameters
$pageName = basename($_SERVER['SCRIPT_NAME']);

// Load template
$oTpl = new OA_Admin_Template('userlog-index.html');

// Get advertisers & publishers for filters
$showAdvertisers = OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER, OA_ACCOUNT_MANAGER, OA_ACCOUNT_ADMIN);
$showPublishers = OA_Permission::isAccount(OA_ACCOUNT_TRAFFICKER, OA_ACCOUNT_MANAGER, OA_ACCOUNT_ADMIN);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,8 +88,8 @@
         $orderdirection = 'up';
     }
 }
-$setPerPage     = MAX_getStoredValue('setPerPage',      10);
-$pageID         = MAX_getStoredValue('pageID',          1);
+$setPerPage     = (int) MAX_getStoredValue('setPerPage',      10);
+$pageID         = (int) MAX_getStoredValue('pageID',          1);
 
 // Setup date selector
 $aPeriod = array(
@@ -205,7 +205,7 @@
     $aParams['startRecord'] = 0;
 }
 
-$aParams['perPage'] = MAX_getStoredValue('setPerPage', 10);
+$aParams['perPage'] = (int) MAX_getStoredValue('setPerPage', 10);
 
 // Retrieve audit details
 $aAuditData = $oUserlog->getAuditLog($aParams);
```
