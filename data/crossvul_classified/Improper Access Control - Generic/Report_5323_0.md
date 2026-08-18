# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5323_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5323_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 12-52 of the vulnerable file.

# Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# GPL: http://www.gnu.org/licenses/gpl.txt
#
##################################################

/**
 * Minimum PHP version check
 */
if (version_compare(PHP_VERSION, '5.3.1', 'lt')) {
    echo "<h1 style='padding:10px;border:5px solid #992222;color:red;background:white;position:absolute;top:100px;left:300px;width:400px;z-index:999'>
        PHP 5.3.1+ is required!  Please refer to the Exponent documentation for details:<br />
        <a href=\"http://docs.exponentcms.org/docs/current/requirements-running-exponent-cms\" target=\"_blank\">http://docs.exponentcms.org/</a>
        </h1>";
    die();
}

ob_start();


// Jumpstart to Initialize the installer language before it's set to default
if (isset($_REQUEST['lang'])) {
    $_REQUEST['sc']['LANGUAGE'] = trim($_REQUEST['lang'], "'");
}
if (isset($_REQUEST['sc']['LANGUAGE'])) {
    if (!defined('LANGUAGE')) {
        define('LANGUAGE', $_REQUEST['sc']['LANGUAGE']);
    }
}

include_once('../exponent.php');
expString::sanitize($_REQUEST);

// Switch to a saved profile as requested
if (isset($_REQUEST['profile'])) {
    expSettings::activateProfile($_REQUEST['profile']);
    expTheme::removeSmartyCache(); //FIXME is this still necessary?
    expSession::clearAllUsersSessionCache();
    flash('message', gt("New Configuration Profile Loaded"));
    header('Location: ../index.php');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,6 @@
 
 ob_start();
 
-
 // Jumpstart to Initialize the installer language before it's set to default
 if (isset($_REQUEST['lang'])) {
     $_REQUEST['sc']['LANGUAGE'] = trim($_REQUEST['lang'], "'");
@@ -42,6 +41,27 @@
 
 include_once('../exponent.php');
 expString::sanitize($_REQUEST);
+
+// Make sure our 'page' is set correctly and prevent running under most circumstances
+if (file_exists("../framework/conf/config.php") && !isset($_REQUEST['page'])) {
+    $_REQUEST['page'] = 'upgrade-1';
+}
+if (!file_exists("../framework/conf/config.php") && !isset($_REQUEST['page'])) {
+    $_REQUEST['page'] = 'welcome';
+}
+$page = $_REQUEST['page'];
+
+// Superadmin must be logged in to do an upgrade
+if (strpos($page, 'upgrade-') !== false && empty($user->isSuperAdmin())) {
+    header('Location: ../index.php');
+    exit();
+}
+
+// Only run installation if not already installed
+if (strpos($page, 'upgrade-') === false && !file_exists(BASE . 'install/not_configured')) {
+    header('Location: ../index.php');
+    exit();
+}
 
 // Switch to a saved profile as requested
 if (isset($_REQUEST['profile'])) {
@@ -57,13 +77,11 @@
     if (file_exists("../framework/conf/config.php")) {
         // Update the config
         foreach ($_REQUEST['sc'] as $key => $value) {
-//            $value = expString::sanitize($value);
             expSettings::change($key, $value);
         }
     } else {
         // Initialize /framework/conf/config
         $values = array(
-//            'c'          => expString::sanitize($_REQUEST['sc']),
             'c'          => $_REQUEST['sc'],
             'opts'       => array(),
             'configname' => 'Default',
@@ -75,6 +93,10 @@
 
 // Install a sample database as requested
 if (isset($_REQUEST['install_sample'])) {
+    if (!empty($_REQUEST['install_sample']) && (strpos($_REQUEST['install_sample'], '..') !== false || strpos($_REQUEST['install_sample'], '/') !== false)) {
+        header('Location: ../index.php');
+        exit();  // attempt to hack the site
+    }
     $eql = BASE . "themes/" . DISPLAY_THEME_REAL . "/" . $_REQUEST['install_sample'] . ".eql";
     if (!file_exists($eql)) {
         $eql = BASE . "install/samples/" . $_REQUEST['install_sample'] . ".eql";
@@ -102,27 +124,6 @@
     } else {
 //        echo gt('Sample content was added to your database.  This content should help you learn how Exponent works, and how to use it for your website.');
     }
-}
-
-// Make sure our 'page' is set correctly
-if (file_exists("../framework/conf/config.php") && !isset($_REQUEST['page'])) {
-    $_REQUEST['page'] = 'upgrade-1';
-}
-if (!file_exists("../framework/conf/config.php") && !isset($_REQUEST['page'])) {
-    $_REQUEST['page'] = 'welcome';
-}
-$page = $_REQUEST['page'];
-
-// Superadmin must be logged in to do an upgrade
-if (strpos($page, 'upgrade-') !== false && empty($user->is_admin)) {
-    header('Location: ../index.php');
-    exit();
-}
-
-// Only run installation if not already installed
-if (strpos($page, 'upgrade-') === false && !file_exists(BASE . 'install/not_configured')) {
-    header('Location: ../index.php');
-    exit();
 }
 
 switch ($page) {
```
