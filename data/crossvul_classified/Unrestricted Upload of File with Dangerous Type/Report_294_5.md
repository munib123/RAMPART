# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_5
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_5`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 127-168 of the vulnerable file.

   <input type='submit' name='bn_search' value='<?php xl('Search', 'e'); ?>' />
   </b>
  </td>
 </tr>
 <tr>
  <td height="1">
  </td>
 </tr>
</table>
</center>
</form>
<form method='post' name='select_immunization'>
<?php if ($_REQUEST['bn_search']) { ?>
<table border='0'>
 <tr>
  <td colspan="4">
<?php
  $search_term = $_REQUEST['search_term'];
  {
    $query = "SELECT count(*) as count FROM list_options " .
      "WHERE (list_id = 'immunizations' and title LIKE '%$search_term%' AND activity = 1) " ;
    $res = sqlStatement($query);
if ($row = sqlFetchArray($res)) {
    $no_of_items = addslashes($row['count']);
    if ($no_of_items < 1) {
        ?>
     <script language='JavaScript'>
        alert("<?php echo xl('Search string does not match with list in database');
        echo '\n';
        echo xl('Please enter new search string');?>");
     document.theform.search_term.value=" ";
     document.theform.search_term.focus();
     </script>
        <?php
    }

    $query = "SELECT option_id,title FROM list_options " .
    "WHERE (list_id = 'immunizations' and title LIKE '%$search_term%' AND activity = 1) " .
    "ORDER BY title";
    $res = sqlStatement($query);
    $row_count = 0;
    while ($row = sqlFetchArray($res)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,8 +144,8 @@
   $search_term = $_REQUEST['search_term'];
   {
     $query = "SELECT count(*) as count FROM list_options " .
-      "WHERE (list_id = 'immunizations' and title LIKE '%$search_term%' AND activity = 1) " ;
-    $res = sqlStatement($query);
+      "WHERE (list_id = 'immunizations' and title LIKE ? AND activity = 1) " ;
+    $res = sqlStatement($query, array('%'.$search_term.'%'));
 if ($row = sqlFetchArray($res)) {
     $no_of_items = addslashes($row['count']);
     if ($no_of_items < 1) {
@@ -161,9 +161,9 @@
     }
 
     $query = "SELECT option_id,title FROM list_options " .
-    "WHERE (list_id = 'immunizations' and title LIKE '%$search_term%' AND activity = 1) " .
+    "WHERE (list_id = 'immunizations' and title LIKE ? AND activity = 1) " .
     "ORDER BY title";
-    $res = sqlStatement($query);
+    $res = sqlStatement($query, array('%'.$search_term.'%'));
     $row_count = 0;
     while ($row = sqlFetchArray($res)) {
         $row_count = $row_count + 1;
```
