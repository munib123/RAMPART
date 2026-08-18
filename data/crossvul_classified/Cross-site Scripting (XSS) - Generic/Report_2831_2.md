# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2831_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2831_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 54-94 of the vulnerable file.

require_once $SETTINGS['cpassman_dir'].'/includes/libraries/protect/SuperGlobal/SuperGlobal.php';
$superGlobal = new protect\SuperGlobal\SuperGlobal();

// Prepare GET variables
$get_group = $superGlobal->get("group", "GET");

// Redirect needed?
if (isset($_SERVER['HTTPS']) === true
    && $_SERVER['HTTPS'] !== 'on'
    && isset($SETTINGS['enable_sts']) === true
    && $SETTINGS['enable_sts'] === "1"
) {
    redirect("https://".$superGlobal->get("HTTP_HOST", "SERVER").$superGlobal->get("REQUEST_URI", "SERVER"));
}


// Load pwComplexity
if (isset($SETTINGS_EXT['pwComplexity']) === false) {
    // Pw complexity levels
    if (isset($_SESSION['user_language']) === true && $_SESSION['user_language'] !== "0") {
        require_once $SETTINGS['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'.php';
        $SETTINGS_EXT['pwComplexity'] = array(
            0=>array(0, $LANG['complex_level0']),
            25=>array(25, $LANG['complex_level1']),
            50=>array(50, $LANG['complex_level2']),
            60=>array(60, $LANG['complex_level3']),
            70=>array(70, $LANG['complex_level4']),
            80=>array(80, $LANG['complex_level5']),
            90=>array(90, $LANG['complex_level6'])
        );
    }
}


// LOAD CPASSMAN SETTINGS
if (isset($SETTINGS_EXT['loaded']) === false || $SETTINGS_EXT['loaded'] !== "1") {
    $SETTINGS_EXT['loaded'] = 1;

    // Should we delete folder INSTALL?
    $row = DB::queryFirstRow(
        "SELECT valeur FROM ".prefix_table("misc")." WHERE type=%s AND intitule=%s",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,7 +71,9 @@
 if (isset($SETTINGS_EXT['pwComplexity']) === false) {
     // Pw complexity levels
     if (isset($_SESSION['user_language']) === true && $_SESSION['user_language'] !== "0") {
-        require_once $SETTINGS['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'.php';
+        if (file_exists($SETTINGS['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'.php') === true) {
+            require_once $SETTINGS['cpassman_dir'].'/includes/language/'.$_SESSION['user_language'].'.php';
+        }
         $SETTINGS_EXT['pwComplexity'] = array(
             0=>array(0, $LANG['complex_level0']),
             25=>array(25, $LANG['complex_level1']),
```
