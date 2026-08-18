# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3002_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3002_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php
/**
 * DokuWiki AJAX call handler
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Andreas Gohr <andi@splitbrain.org>
 */

if(!defined('DOKU_INC')) define('DOKU_INC',dirname(__FILE__).'/../../');
require_once(DOKU_INC.'inc/init.php');
//close session
session_write_close();

header('Content-Type: text/html; charset=utf-8');

//call the requested function
if($INPUT->post->has('call')){
    $call = $INPUT->post->str('call');
}else if($INPUT->get->has('call')){
    $call = $INPUT->get->str('call');
}else{
    exit;
}
$callfn = 'ajax_'.$call;

if(function_exists($callfn)){
    $callfn();
}else{
    $evt = new Doku_Event('AJAX_CALL_UNKNOWN', $call);
    if ($evt->advise_before()) {
        print "AJAX call '".htmlspecialchars($call)."' unknown!\n";
        exit;
    }
    $evt->advise_after();
    unset($evt);
}

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,9 +15,9 @@
 
 //call the requested function
 if($INPUT->post->has('call')){
-    $call = $INPUT->post->str('call');
+    $call = $INPUT->post->filter('utf8_stripspecials')->str('call');
 }else if($INPUT->get->has('call')){
-    $call = $INPUT->get->str('call');
+    $call = $INPUT->get->filter('utf8_stripspecials')->str('call');
 }else{
     exit;
 }
```
