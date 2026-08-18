# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4134_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4134_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 581-621 of the vulnerable file.

Session::start();
error_reporting(0); // we want to check system before affraid the user.

if (isset($_POST["language"])) {
   $_SESSION["glpilanguage"] = $_POST["language"];
}

Session::loadLanguage('', false);

/**
 * @since 0.84.2
**/
function checkConfigFile() {

   if (file_exists(GLPI_CONFIG_DIR . "/config_db.php")) {
      Html::redirect($CFG_GLPI['root_doc'] ."/index.php");
      die();
   }
}

if (!isset($_POST["install"])) {
   $_SESSION = [];

   checkConfigFile();
   header_html("Select your language");
   choose_language();

} else {
   // Check valid Referer :
   Toolbox::checkValidReferer();
   // Check CSRF: ensure nobody strap first page that checks if config file exists ...
   Session::checkCSRF($_POST);

   // DB clean
   if (isset($_POST["db_pass"])) {
      $_POST["db_pass"] = stripslashes($_POST["db_pass"]);
      $_POST["db_pass"] = rawurldecode($_POST["db_pass"]);
      $_POST["db_pass"] = stripslashes($_POST["db_pass"]);
   }

   switch ($_POST["install"]) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -598,10 +598,17 @@
    }
 }
 
-if (!isset($_POST["install"])) {
+if (!isset($_SESSION['can_process_install']) || !isset($_POST["install"])) {
    $_SESSION = [];
 
    checkConfigFile();
+
+   // Add a flag that will be used to validate that installation can be processed.
+   // This flag is put here just after checking that DB config file does not exist yet.
+   // It is mandatory to validate that `Etape_4` to `Etape_6` are not used outside installation process
+   // to change GLPI base URL without even being authenticated.
+   $_SESSION['can_process_install'] = true;
+
    header_html("Select your language");
    choose_language();
 
```
