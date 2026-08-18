# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 4267_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4267_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 1-34 of the vulnerable file.

<?php

require_once '../../videos/configuration.php';
session_write_close();
try {
    $global['mysqli']->close();
} catch (Exception $exc) {
    //echo $exc->getTraceAsString();
}


/*
 * this file is to handle HTTP URLs into HTTPS
 */
if (!filter_var($_GET['livelink'], FILTER_VALIDATE_URL) && preg_match("/^http.*/i", $_GET['livelink'])) {
    echo "Invalid Link";
    exit;
}
header("Content-Type: video/vnd.mpegurl");
header("Content-Disposition: attachment;filename=playlist.m3u");
$content = url_get_contents($_GET['livelink']);
$pathinfo = pathinfo($_GET['livelink']); 
foreach (preg_split("/((\r?\n)|(\r\n?))/", $content) as $line) {
    $line = trim($line);
    if (!empty($line) && $line[0] !== "#") {
        if (!filter_var($line, FILTER_VALIDATE_URL)) {
            if(!empty($pathinfo["extension"])){
                $_GET['livelink'] = str_replace($pathinfo["basename"], "", $_GET['livelink']);
            }
            $line = $_GET['livelink'].$line;
        }
    }
    echo $line.PHP_EOL;
} 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,7 @@
 /*
  * this file is to handle HTTP URLs into HTTPS
  */
-if (!filter_var($_GET['livelink'], FILTER_VALIDATE_URL) && preg_match("/^http.*/i", $_GET['livelink'])) {
+if (!filter_var($_GET['livelink'], FILTER_VALIDATE_URL) || !preg_match("/^http.*/i", $_GET['livelink'])) {
     echo "Invalid Link";
     exit;
 }
```
