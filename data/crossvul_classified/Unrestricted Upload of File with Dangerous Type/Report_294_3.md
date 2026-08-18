# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_3
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_3`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 155-196 of the vulnerable file.

   <input type='submit' name='bn_search' id='bn_search' value='<?php xl('Search', 'e'); ?>' />
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
<form method='post' name='select_diagonsis'>
<table border='0'>
 <tr>
 <td colspan="4">
<?php if ($_REQUEST['bn_search']) {
    $search_term = $_REQUEST['search_term'];
    if ($form_code_type == 'PROD') {
        $query = "SELECT dt.drug_id, dt.selector, d.name " .
        "FROM drug_templates AS dt, drugs AS d WHERE " .
        "( d.name LIKE '%$search_term%' OR " .
        "dt.selector LIKE '%$search_term%' ) " .
        "AND d.drug_id = dt.drug_id " .
        "ORDER BY d.name, dt.selector, dt.drug_id";
        $res = sqlStatement($query);
        $row_count = 0;
        while ($row = sqlFetchArray($res)) {
            $row_count = $row_count + 1;
            $drug_id = addslashes($row['drug_id']);
            $selector = addslashes($row['selector']);
            $desc = addslashes($row['name']);
            ?>
             <input type="checkbox" name="diagnosis[row_count]" value= "<?php echo $desc; ?>" > <?php echo $drug_id."    ".$selector."     ".$desc."</br>";
        }
    } else {
        $query = "SELECT count(*) as count FROM codes " .
        "WHERE (code_text LIKE '%$search_term%' OR " .
        "code LIKE '%$search_term%') " ;
        $res = sqlStatement($query);
        if ($row = sqlFetchArray($res)) {
            $no_of_items = addslashes($row['count']);
            if ($no_of_items < 1) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -172,11 +172,11 @@
     if ($form_code_type == 'PROD') {
         $query = "SELECT dt.drug_id, dt.selector, d.name " .
         "FROM drug_templates AS dt, drugs AS d WHERE " .
-        "( d.name LIKE '%$search_term%' OR " .
-        "dt.selector LIKE '%$search_term%' ) " .
+        "( d.name LIKE ? OR " .
+        "dt.selector LIKE ? ) " .
         "AND d.drug_id = dt.drug_id " .
         "ORDER BY d.name, dt.selector, dt.drug_id";
-        $res = sqlStatement($query);
+        $res = sqlStatement($query, array('%'.$search_term.'%', '%'.$search_term.'%'));
         $row_count = 0;
         while ($row = sqlFetchArray($res)) {
             $row_count = $row_count + 1;
@@ -188,9 +188,9 @@
         }
     } else {
         $query = "SELECT count(*) as count FROM codes " .
-        "WHERE (code_text LIKE '%$search_term%' OR " .
-        "code LIKE '%$search_term%') " ;
-        $res = sqlStatement($query);
+        "WHERE (code_text LIKE ? OR " .
+        "code LIKE ?) " ;
+        $res = sqlStatement($query, array('%'.$search_term.'%', '%'.$search_term.'%'));
         if ($row = sqlFetchArray($res)) {
             $no_of_items = addslashes($row['count']);
             if ($no_of_items < 1) {
@@ -206,11 +206,11 @@
             }
 
             $query = "SELECT code_type, code, modifier, code_text FROM codes " .
-            "WHERE (code_text LIKE '%$search_term%' OR " .
-            "code LIKE '%$search_term%') " .
+            "WHERE (code_text LIKE ? OR " .
+            "code LIKE ?) " .
             "ORDER BY code";
           // echo "\n<!-- $query -->\n"; // debugging
-            $res = sqlStatement($query);
+            $res = sqlStatement($query, array('%'.$search_term.'%', '%'.$search_term.'%'));
             $row_count = 0;
             while ($row = sqlFetchArray($res)) {
                 $row_count = $row_count + 1;
```
