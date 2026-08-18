# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_7
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_7`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 12-52 of the vulnerable file.

use OpenEMR\Core\Header;

$faxstats = array(
'B' => xl('Blocked'),
'D' => xl('Sent successfully'),
'F' => xl('Failed'),
'P' => xl('Pending'),
'R' => xl('Send in progress'),
'S' => xl('Sleeping'),
'T' => xl('Suspended'),
'W' => xl('Waiting')
);

$mlines = array();
$dlines = array();
$slines = array();

if ($GLOBALS['enable_hylafax']) {
// Get the recvq entries, parse and sort by filename.
    $statlines = array();
    exec("faxstat -r -l -h " . $GLOBALS['hylafax_server'], $statlines);
    foreach ($statlines as $line) {
        // This gets pagecount, sender, time, filename.  We are expecting the
        // string to start with "-rw-rw-" so as to exclude faxes not yet fully
        // received, for which permissions are "-rw----".
        if (preg_match('/^-r\S\Sr\S\S\s+(\d+)\s+\S+\s+(.+)\s+(\S+)\s+(\S+)\s*$/', $line, $matches)) {
            $mlines[$matches[4]] = $matches;
        }
    }

    ksort($mlines);

    // Get the doneq entries, parse and sort by job ID
    /* for example:
    JID  Pri S  Owner Number       Pages Dials     TTS Status
    155  123 D nobody 6158898622    1:1   5:12
    153  124 D nobody 6158896439    1:1   4:12
    154  124 F nobody 6153551807    0:1   4:12         No carrier detected
    */
    $donelines = array();
    exec("faxstat -s -d -l -h " . $GLOBALS['hylafax_server'], $donelines);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,7 @@
 if ($GLOBALS['enable_hylafax']) {
 // Get the recvq entries, parse and sort by filename.
     $statlines = array();
-    exec("faxstat -r -l -h " . $GLOBALS['hylafax_server'], $statlines);
+    exec("faxstat -r -l -h " . escapeshellarg($GLOBALS['hylafax_server']), $statlines);
     foreach ($statlines as $line) {
         // This gets pagecount, sender, time, filename.  We are expecting the
         // string to start with "-rw-rw-" so as to exclude faxes not yet fully
```
