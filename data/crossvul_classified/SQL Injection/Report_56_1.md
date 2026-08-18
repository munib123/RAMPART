# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 56_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `56_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.

include 'loggedin.inc.php';
include MAIN_PATH . 'language/' . $language . '/categories.inc.php';
include PACKAGE_PATH . 'ckeditor/ckeditor.php';

$catscontrol = new MPTTcategories();

// Data check
if (!isset($_REQUEST['id'])) {
    $URL = $_SESSION['RETURN_LIST'];
    header('location: ' . $URL);
    exit;
}

function load_gallery($auc_id)
{
    $UPLOADED_PICTURES = array();
    if (is_dir(UPLOAD_PATH . $auc_id)) {
        if ($dir = opendir(UPLOAD_PATH . $auc_id)) {
            while ($file = @readdir($dir)) {
                if ($file != '.' && $file != '..' && strpos($file, 'thumb-') === false) {
                    $UPLOADED_PICTURES[] = UPLOAD_FOLDER . $auc_id . '/' . $file;
                }
            }
            closedir($dir);
        }
    }
    return $UPLOADED_PICTURES;
}

if (isset($_POST['action'])) {
    // Check that all the fields are not NULL
    if (!empty($_POST['id']) && !empty($_POST['title']) && !empty($_POST['duration']) && !empty($_POST['category']) && !empty($_POST['description']) && !empty($_POST['min_bid'])) {
        // fix values
        $_POST['quantity'] = (empty($_POST['quantity'])) ? 1 : $_POST['quantity'];
        $_POST['customincrement'] = (empty($_POST['customincrement'])) ? 0 : $_POST['customincrement'];
        // Check the input values for validity.
        if ($_POST['quantity'] < 1) { // 1 or more items being sold
            $template->assign_block_vars('alerts', array('TYPE' => 'error', 'MESSAGE' => $ERR_601));
        } elseif (isset($_POST['current_bid']) && $_POST['current_bid'] < $_POST['min_bid'] && $_POST['current_bid'] != 0) { // bid > min_bid
            $template->assign_block_vars('alerts', array('TYPE' => 'error', 'MESSAGE' => $MSG['error_current_bid_too_low']));
        } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
         if ($dir = opendir(UPLOAD_PATH . $auc_id)) {
             while ($file = @readdir($dir)) {
                 if ($file != '.' && $file != '..' && strpos($file, 'thumb-') === false) {
-                    $UPLOADED_PICTURES[] = UPLOAD_FOLDER . $auc_id . '/' . $file;
+                    $UPLOADED_PICTURES[] = $file;
                 }
             }
             closedir($dir);
```
