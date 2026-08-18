# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2831_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2831_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 160-200 of the vulnerable file.

} elseif ($session_user_language === null || empty($session_user_language) === true) {
    if (null !== $post_language) {
        $superGlobal->put("user_language", $post_language, "SESSION");
        $session_user_language = $post_language;
    } elseif ($session_user_language !== null) {
        $superGlobal->put("user_language", $SETTINGS['default_language'], "SESSION");
        $session_user_language = $SETTINGS['default_language'];
    }
} elseif ($session_user_language === '0') {
    $superGlobal->put("user_language", $SETTINGS['default_language'], "SESSION");
    $session_user_language = $SETTINGS['default_language'];
}

if (isset($SETTINGS['cpassman_dir']) === false || $SETTINGS['cpassman_dir'] === "") {
    $SETTINGS['cpassman_dir'] = ".";
    $SETTINGS['cpassman_url'] = (string) $server_request_uri;
}

// Load user languages files
if (in_array($session_user_language, $languagesList) === true) {
    require_once $SETTINGS['cpassman_dir'].'/includes/language/'.$session_user_language.'.php';
} else {
    $_SESSION['error']['code'] = ERR_NOT_ALLOWED; //not allowed page
    include $SETTINGS['cpassman_dir'].'/error.php';
}

// load 2FA Google
if (isset($SETTINGS['google_authentication']) === true && $SETTINGS['google_authentication'] === "1") {
    include_once($SETTINGS['cpassman_dir']."/includes/libraries/Authentication/TwoFactorAuth/TwoFactorAuth.php");
}

// Load links, css and javascripts
if (isset($_SESSION['CPM']) === true && isset($SETTINGS['cpassman_dir']) === true) {
    require_once $SETTINGS['cpassman_dir'].'/load.php';
}

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -177,7 +177,9 @@
 
 // Load user languages files
 if (in_array($session_user_language, $languagesList) === true) {
-    require_once $SETTINGS['cpassman_dir'].'/includes/language/'.$session_user_language.'.php';
+    if (file_exists($SETTINGS['cpassman_dir'].'/includes/language/'.$session_user_language.'.php') === true) {
+        require_once $SETTINGS['cpassman_dir'].'/includes/language/'.$session_user_language.'.php';
+    }
 } else {
     $_SESSION['error']['code'] = ERR_NOT_ALLOWED; //not allowed page
     include $SETTINGS['cpassman_dir'].'/error.php';
```
