# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_8
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_8`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 7-47 of the vulnerable file.

 // of the License, or (at your option) any later version.

 // This script runs in a hidden frame, reloads itself periodically,
 // and does whatever might need doing in the background.

 // Tell auth.inc that this is the daemon script; this is so that
 // inactivity timeouts will still work, and to avoid logging an
 // event every time we run.
 $GLOBALS['DAEMON_FLAG'] = true;

 include_once("../globals.php");

 $daemon_interval = 120; // Interval in seconds between reloads.
 $colorh = '#ff0000';    // highlight color
 $colorn = '#000000';    // normal color

 // Check if there are faxes in the recvq.
 $faxcount = 0;
if ($GLOBALS['enable_hylafax']) {
    $statlines = array();
    exec("faxstat -r -l -h " . $GLOBALS['hylafax_server'], $statlines);
    foreach ($statlines as $line) {
        if (substr($line, 0, 1) == '-') {
            ++$faxcount;
        }
    }
}

 $color_fax = $faxcount ? $colorh : $colorn;

 // Check if this user has any active patient notes assigned to them.
 $row = sqlQuery("SELECT count(*) AS count FROM pnotes WHERE " .
  "activity = 1 ".
  " AND deleted != 1 ". // exlude ALL deleted notes
  " AND assigned_to = '" . $_SESSION['authUser'] . "'");
 $color_aun = $row['count'] ? $colorh : $colorn;
?>
<html>
<body bgcolor="#000000">
<script language='JavaScript'>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,7 @@
  $faxcount = 0;
 if ($GLOBALS['enable_hylafax']) {
     $statlines = array();
-    exec("faxstat -r -l -h " . $GLOBALS['hylafax_server'], $statlines);
+    exec("faxstat -r -l -h " . escapeshellarg($GLOBALS['hylafax_server']), $statlines);
     foreach ($statlines as $line) {
         if (substr($line, 0, 1) == '-') {
             ++$faxcount;
```
