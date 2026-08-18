# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 2535_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2535_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 1-46 of the vulnerable file.

<?php

/**
 * @file
 *
 * csrf-magic is a PHP library that makes adding CSRF-protection to your
 * web applications a snap. No need to modify every form or create a database
 * of valid nonces; just include this file at the top of every
 * web-accessible page (or even better, your common include file included
 * in every page), and forget about it! (There are, of course, configuration
 * options for advanced users).
 *
 * This library is PHP4 and PHP5 compatible.
 */

// CONFIGURATION:

/**
 * By default, when you include this file csrf-magic will automatically check
 * and exit if the CSRF token is invalid. This will defer executing
 * csrf_check() until you're ready.  You can also pass false as a parameter to
 * that function, in which case the function will not exit but instead return
 * a boolean false if the CSRF check failed. This allows for tighter integration
 * with your system.
 */
$GLOBALS['csrf']['defer'] = false;

/**
 * This is the amount of seconds you wish to allow before any token becomes
 * invalid; the default is two hours, which should be more than enough for
 * most websites.
 */
$GLOBALS['csrf']['expires'] = 7200;

/**
 * Callback function to execute when there's the CSRF check fails and
 * $fatal == true (see csrf_check). This will usually output an error message
 * about the failure.
 */
$GLOBALS['csrf']['callback'] = 'csrf_callback';

/**
 * Whether or not to include our JavaScript library which also rewrites
 * AJAX requests on this domain. Set this to the web path. This setting only works
 * with supported JavaScript libraries in Internet Explorer; see README.txt for
 * a list of supported libraries.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,16 +14,6 @@
  */
 
 // CONFIGURATION:
-
-/**
- * By default, when you include this file csrf-magic will automatically check
- * and exit if the CSRF token is invalid. This will defer executing
- * csrf_check() until you're ready.  You can also pass false as a parameter to
- * that function, in which case the function will not exit but instead return
- * a boolean false if the CSRF check failed. This allows for tighter integration
- * with your system.
- */
-$GLOBALS['csrf']['defer'] = false;
 
 /**
  * This is the amount of seconds you wish to allow before any token becomes
@@ -118,12 +108,6 @@
 $GLOBALS['csrf']['frame-breaker'] = true;
 
 /**
- * Whether or not CSRF Magic should be allowed to start a new session in order
- * to determine the key.
- */
-$GLOBALS['csrf']['auto-session'] = true;
-
-/**
  * Whether or not csrf-magic should produce XHTML style tags.
  */
 $GLOBALS['csrf']['xhtml'] = true;
@@ -187,7 +171,6 @@
     if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
         return true;
     }
-    csrf_start();
     $name = $GLOBALS['csrf']['input-name'];
     $ok = false;
     $tokens = '';
@@ -232,7 +215,6 @@
     } else {
         $ip = '';
     }
-    csrf_start();
 
     // These are "strong" algorithms that don't require per se a secret
     if (session_id()) {
@@ -259,27 +241,6 @@
     return 'invalid';
 }
 
-function csrf_flattenpost($data)
-{
-    $ret = array();
-    foreach ($data as $n => $v) {
-        $ret = array_merge($ret, csrf_flattenpost2(1, $n, $v));
-    }
-    return $ret;
-}
-function csrf_flattenpost2($level, $key, $data)
-{
-    if (!is_array($data)) {
-        return array($key => $data);
-    }
-    $ret = array();
-    foreach ($data as $n => $v) {
-        $nk = $level >= 1 ? $key."[$n]" : "[$n]";
-        $ret = array_merge($ret, csrf_flattenpost2($level+1, $nk, $v));
-    }
-    return $ret;
-}
-
 /**
  * @param $tokens is safe for HTML consumption
  */
@@ -287,18 +248,11 @@
 {
     // (yes, $tokens is safe to echo without escaping)
     header($_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden');
-    $data = '';
-    foreach (csrf_flattenpost($_POST) as $key => $value) {
-        if ($key == $GLOBALS['csrf']['input-name']) {
-            continue;
-        }
-        $data .= '<input type="hidden" name="'.htmlspecialchars($key).'" value="'.htmlspecialchars($value).'" />';
-    }
+
     echo "<html><head><title>CSRF check failed</title></head>
         <body>
         <p>CSRF check failed. Your form session may have expired, or you may not have
         cookies enabled.</p>
-        <form method='post' action=''>$data<input type='submit' value='Try again' /></form>
         <p>Debug: $tokens</p></body></html>
 ";
 }
@@ -396,16 +350,6 @@
         return;
     }
     $GLOBALS['csrf'][$key] = $val;
-}
-
-/**
- * Starts a session if we're allowed to.
- */
-function csrf_start()
-{
-    if ($GLOBALS['csrf']['auto-session'] && session_status() == PHP_SESSION_NONE) {
-        session_start();
-    }
 }
 
 /**
@@ -469,6 +413,4 @@
     ob_start('csrf_ob_handler');
 }
 // Perform check
-if (!$GLOBALS['csrf']['defer']) {
-    csrf_check();
-}
+csrf_check();
```
