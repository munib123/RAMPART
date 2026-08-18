# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5090_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5090_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 69-109 of the vulnerable file.

        $response = PMA\libraries\Response::getInstance();
        $response->setRequestStatus(false);
        $response->addJSON('message', __('No row selected.'));
    }

    switch($submit_mult) {
    /** @noinspection PhpMissingBreakStatementInspection */
    case 'row_copy':
        $_REQUEST['default_action'] = 'insert';
        // no break to allow for fallthough
    case 'row_edit':
        // As we got the rows to be edited from the
        // 'rows_to_delete' checkbox, we use the index of it as the
        // indicating WHERE clause. Then we build the array which is used
        // for the tbl_change.php script.
        $where_clause = array();
        if (isset($_REQUEST['rows_to_delete'])
            && is_array($_REQUEST['rows_to_delete'])
        ) {
            foreach ($_REQUEST['rows_to_delete'] as $i => $i_where_clause) {
                $where_clause[] = urldecode($i_where_clause);
            }
        }
        $active_page = 'tbl_change.php';
        include 'tbl_change.php';
        break;

    case 'row_export':
        // Needed to allow SQL export
        $single_table = true;

        // As we got the rows to be exported from the
        // 'rows_to_delete' checkbox, we use the index of it as the
        // indicating WHERE clause. Then we build the array which is used
        // for the tbl_change.php script.
        $where_clause = array();
        if (isset($_REQUEST['rows_to_delete'])
            && is_array($_REQUEST['rows_to_delete'])
        ) {
            foreach ($_REQUEST['rows_to_delete'] as $i => $i_where_clause) {
                $where_clause[] = urldecode($i_where_clause);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,7 +86,7 @@
             && is_array($_REQUEST['rows_to_delete'])
         ) {
             foreach ($_REQUEST['rows_to_delete'] as $i => $i_where_clause) {
-                $where_clause[] = urldecode($i_where_clause);
+                $where_clause[] = $i_where_clause;
             }
         }
         $active_page = 'tbl_change.php';
@@ -106,7 +106,7 @@
             && is_array($_REQUEST['rows_to_delete'])
         ) {
             foreach ($_REQUEST['rows_to_delete'] as $i => $i_where_clause) {
-                $where_clause[] = urldecode($i_where_clause);
+                $where_clause[] = $i_where_clause;
             }
         }
         $active_page = 'tbl_export.php';
```
