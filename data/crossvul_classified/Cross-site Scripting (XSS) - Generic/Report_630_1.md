# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 630_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `630_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 73-113 of the vulnerable file.

    $selected_fld = $_REQUEST['selected_fld'];
    $selected_db = $_REQUEST['db'];
    $edit_central_column_page = PMA_getHTMLforEditingPage(
        $selected_fld, $selected_db
    );
    $response->addHTML($edit_central_column_page);
    exit;
}
if (isset($_POST['multi_edit_central_column_save'])) {
    $message = PMA_updateMultipleColumn();
    if (!is_bool($message)) {
        $response->setRequestStatus(false);
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
if (PMA_isValid($_REQUEST['pos'], 'integer')) {
    $pos = intval($_REQUEST['pos']);
} else {
    $pos = 0;
}
$addNewColumn = PMA_getHTMLforAddNewColumn($db, $total_rows);
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -90,7 +90,9 @@
     parse_str($_POST['col_name'], $col_name);
     $tmp_msg = PMA_deleteColumnsFromList($col_name['selected_fld'], false);
 }
-if (isset($_REQUEST['total_rows']) && $_REQUEST['total_rows']) {
+if (!empty($_REQUEST['total_rows'])
+    && PMA_isValid($_REQUEST['total_rows'], 'integer')
+) {
     $total_rows = $_REQUEST['total_rows'];
 } else {
     $total_rows = PMA_getCentralColumnsCount($db);
```
