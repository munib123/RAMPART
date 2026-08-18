# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4298_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4298_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 38-78 of the vulnerable file.

    $_REQUEST['exportFormat'] = $_SESSION['export']['format'];
  if ( isset($_SESSION['export']['compress']) )
    $_REQUEST['exportCompress'] = $_SESSION['export']['compress'];
} else {
  $_REQUEST['exportDetail'] =
  $_REQUEST['exportFrames'] =
  $_REQUEST['exportImages'] =
  $_REQUEST['exportVideo'] =
  $_REQUEST['exportMisc'] = 1;
  $_REQUEST['exportCompress'] = 0;
}

if (isset($_REQUEST['exportFormat'])) {
  if (!in_array($_REQUEST['exportFormat'], array('zip', 'tar'))) {
    ZM\Error('Invalid exportFormat');
    return;
  }
}

$focusWindow = true;
$connkey = isset($_REQUEST['connkey']) ? $_REQUEST['connkey'] : generateConnKey();

xhtmlHeaders(__FILE__, translate('Export'));
?>
<body>
  <div id="page">
    <?php echo getNavBarHTML() ?>
    <div id="header">
      <h2><?php echo translate('ExportOptions') ?></h2>
    </div>
    <div id="content">
      <form name="contentForm" id="contentForm" method="post" action="?view=export">
        <input type="hidden" name="connkey" value="<?php echo $connkey; ?>"/>
<?php

$eventsSql = 'SELECT E.*,M.Name AS MonitorName FROM Monitors AS M INNER JOIN Events AS E on (M.Id = E.MonitorId) WHERE';
$eventsValues = array();
$filterQuery = '';
$sortColumn = '';
$sortOrder = '';
$limitQuery = '';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,7 +55,7 @@
 }
 
 $focusWindow = true;
-$connkey = isset($_REQUEST['connkey']) ? $_REQUEST['connkey'] : generateConnKey();
+$connkey = isset($_REQUEST['connkey']) ? validInt($_REQUEST['connkey']) : generateConnKey();
 
 xhtmlHeaders(__FILE__, translate('Export'));
 ?>
```
