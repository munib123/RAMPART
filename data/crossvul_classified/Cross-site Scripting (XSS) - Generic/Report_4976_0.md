# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4976_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4976_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 55-95 of the vulnerable file.

    echo $html;
    exit;
}

if (isset($_REQUEST['getNewTables3NF'])) {
    $dependencies = json_decode($_REQUEST['pd']);
    $tables = json_decode($_REQUEST['tables']);
    $newTables = PMA_getHtmlForNewTables3NF($dependencies, $tables, $db);
    PMA_Response::getInstance()->disable();
    PMA_headerJSON();
    echo json_encode($newTables);
    exit;
}

$response = PMA_Response::getInstance();
$header = $response->getHeader();
$scripts = $header->getScripts();
$scripts->addFile('normalization.js');
$scripts->addFile('jquery/jquery.uitablefilter.js');
$normalForm = '1nf';
if (isset($_REQUEST['normalizeTo'])) {
    $normalForm = $_REQUEST['normalizeTo'];
}
if (isset($_REQUEST['createNewTables2NF'])) {
    $partialDependencies = json_decode($_REQUEST['pd']);
    $tablesName = json_decode($_REQUEST['newTablesName']);
    $res = PMA_createNewTablesFor2NF($partialDependencies, $tablesName, $table, $db);
    $response->addJSON($res);
    exit;
}
if (isset($_REQUEST['createNewTables3NF'])) {
    $newtables = json_decode($_REQUEST['newTables']);
    $res = PMA_createNewTablesFor3NF($newtables, $db);
    $response->addJSON($res);
    exit;
}
if (isset($_POST['repeatingColumns'])) {
    $repeatingColumns = $_POST['repeatingColumns'];
    $newTable = $_POST['newTable'];
    $newColumn = $_POST['newColumn'];
    $primary_columns = $_POST['primary_columns'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,7 @@
 $scripts->addFile('normalization.js');
 $scripts->addFile('jquery/jquery.uitablefilter.js');
 $normalForm = '1nf';
-if (isset($_REQUEST['normalizeTo'])) {
+if (PMA_isValid($_REQUEST['normalizeTo'], array('1nf', '2nf', '3nf'))) {
     $normalForm = $_REQUEST['normalizeTo'];
 }
 if (isset($_REQUEST['createNewTables2NF'])) {
```
