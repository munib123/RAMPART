# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4979_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4979_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 75-115 of the vulnerable file.

    $response->addHTML($edit_central_column_page);
    exit;
}
if (isset($_POST['multi_edit_central_column_save'])) {
    $message = PMA_updateMultipleColumn();
    if (!is_bool($message)) {
        $response->isSuccess(false);
        $response->addJSON('message', $message);
    }
}
if (isset($_POST['delete_save'])) {
    $col_name = array();
    parse_str($_POST['col_name'], $col_name);
    $tmp_msg = PMA_deleteColumnsFromList($col_name['selected_fld'], false);
}
if (isset($_REQUEST['total_rows']) && $_REQUEST['total_rows']) {
    $total_rows = $_REQUEST['total_rows'];
} else {
    $total_rows = PMA_getCentralColumnsCount($db);
}
if (isset($_REQUEST['pos'])) {
    $pos = $_REQUEST['pos'];
} else {
    $pos = 0;
}
$addNewColumn = PMA_getHTMLforAddNewColumn($db);
$response->addHTML($addNewColumn);
if ($total_rows <= 0) {
    $response->addHTML(
        '<fieldset>' . __(
            'The central list of columns for the current database is empty.'
        ) . '</fieldset>'
    );
    $columnAdd = PMA_getHTMLforAddCentralColumn($total_rows, $pos, $db);
    $response->addHTML($columnAdd);
    exit;
}
$table_navigation_html = PMA_getHTMLforTableNavigation($total_rows, $pos, $db);
$response->addHTML($table_navigation_html);
$columnAdd = PMA_getHTMLforAddCentralColumn($total_rows, $pos, $db);
$response->addHTML($columnAdd);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -92,7 +92,7 @@
 } else {
     $total_rows = PMA_getCentralColumnsCount($db);
 }
-if (isset($_REQUEST['pos'])) {
+if (PMA_isValid($_REQUEST['pos'], 'integer')) {
     $pos = $_REQUEST['pos'];
 } else {
     $pos = 0;
```
