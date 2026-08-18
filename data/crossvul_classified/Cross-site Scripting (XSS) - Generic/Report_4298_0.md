# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4298_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4298_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 45-85 of the vulnerable file.

#Logger::Debug("NO montageReviewFilter");
}

$exportFormat = '';
if ( isset($_REQUEST['exportFormat']) ) {
  if ( !in_array($_REQUEST['exportFormat'], array('zip', 'tar')) ) {
    ZM\Error('Invalid exportFormat: '.$_REQUEST['exportFormat']);
  } else {
    $exportFormat = $_REQUEST['exportFormat'];
  }
}

if ( !empty($_REQUEST['eid']) ) {
  $Event = new ZM\Event($_REQUEST['eid']);
  if ( !$Event->Id ) {
    Error('Invalid event id');
  }
}

$focusWindow = true;
$connkey = isset($_REQUEST['connkey']) ? $_REQUEST['connkey'] : generateConnKey();

xhtmlHeaders(__FILE__, translate('Download'));
?>
<body>
  <div id="page">
    <div id="header">
      <div id="headerButtons">
        <a href="#" data-on-click="closeWindow"><?php echo translate('Close') ?></a>
      </div>
      <h2><?php echo translate('Download') ?></h2>
    </div>
    <div id="content">
      <form name="contentForm" id="contentForm" method="post" action="<?php echo $_SERVER['PHP_SELF'] ?>">
        <input type="hidden" name="connkey" value="<?php echo $connkey; ?>"/>
<?php
if ( !empty($_REQUEST['eid']) ) {
?>
        <input type="hidden" name="id" value="<?php echo validInt($_REQUEST['eid']) ?>"/>
    <?php
    $Event = new ZM\Event($_REQUEST['eid']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,7 +62,7 @@
 }
 
 $focusWindow = true;
-$connkey = isset($_REQUEST['connkey']) ? $_REQUEST['connkey'] : generateConnKey();
+$connkey = isset($_REQUEST['connkey']) ? validInt($_REQUEST['connkey']) : generateConnKey();
 
 xhtmlHeaders(__FILE__, translate('Download'));
 ?>
@@ -75,7 +75,7 @@
       <h2><?php echo translate('Download') ?></h2>
     </div>
     <div id="content">
-      <form name="contentForm" id="contentForm" method="post" action="<?php echo $_SERVER['PHP_SELF'] ?>">
+      <form name="contentForm" id="contentForm" method="post" action="?">
         <input type="hidden" name="connkey" value="<?php echo $connkey; ?>"/>
 <?php
 if ( !empty($_REQUEST['eid']) ) {
```
