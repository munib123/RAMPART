# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in php
**Pair ID:** 5772_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5772_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```php
Lines 104-144 of the vulnerable file.

;
if ($_POST == array() && $_GET == array()) {
    $message = PMA_Message::error(
        __('You probably tried to upload a file that is too large. Please refer to %sdocumentation%s for a workaround for this limit.')
    );
    $message->addParam('[doc@faq1-16]');
    $message->addParam('[/doc]');

    // so we can obtain the message
    $_SESSION['Import_message']['message'] = $message->getDisplay();
    $_SESSION['Import_message']['go_back_url'] = $goto;

    $message->display();
    exit; // the footer is displayed automatically
}

/**
 * Sets globals from $_POST patterns, for import plugins
 * We only need to load the selected plugin
 */

$post_patterns = array(
    '/^force_file_/',
    '/^'. $format . '_/'
);
foreach (array_keys($_POST) as $post_key) {
    foreach ($post_patterns as $one_post_pattern) {
        if (preg_match($one_post_pattern, $post_key)) {
            $GLOBALS[$post_key] = $_POST[$post_key];
        }
    }
}

// Check needed parameters
PMA_Util::checkParameters(array('import_type', 'format'));

// We don't want anything special in format
$format = PMA_securePath($format);

// Import functions
require_once 'libraries/import.lib.php';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,6 +121,24 @@
  * Sets globals from $_POST patterns, for import plugins
  * We only need to load the selected plugin
  */
+
+if (! in_array(
+    $format, 
+    array(
+        'csv',
+        'ldi',
+        'mediawiki',
+        'ods',
+        'shp',
+        'sql',
+        'xml'
+    )
+)
+) {
+    // this should not happen for a normal user
+    // but only during an attack
+    PMA_fatalError('Incorrect format parameter');
+}
 
 $post_patterns = array(
     '/^force_file_/',
```
