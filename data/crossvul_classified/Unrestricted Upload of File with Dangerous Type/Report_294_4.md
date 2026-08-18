# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 294_4
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `294_4`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 21-61 of the vulnerable file.

require_once("$srcdir/patient.inc");
require_once("../../custom/code_types.inc.php");

$info_msg = "";
$codetype = $_REQUEST['codetype'];
$form_code_type = $_POST['form_code_type'];
?>
<html>
<head>
<?php html_header_show(); ?>
<title><?php xl('Drug Finder', 'e'); ?></title>
<link rel="stylesheet" href='<?php echo $css_header ?>' type='text/css'>

<style>
td { font-size:10pt; }
</style>

<script language="JavaScript">
//pass value selected to the parent window
 function window_submit(chk)
 { 
  var str;
  var len=chk.length;
  if (len==undefined && chk.checked==1) 
  {
    if(!str)
      str = chk.value;
    else  
    str = "#"+chk.value;
  }
  else
  {
  for (pr = 0; pr < chk.length; pr++)
   {
    if(chk[pr].checked == 1)
    {
     if(!str)
      str = chk[pr].value;
     else 
      str = str+"#"+chk[pr].value;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,14 +38,14 @@
 <script language="JavaScript">
 //pass value selected to the parent window
  function window_submit(chk)
- { 
+ {
   var str;
   var len=chk.length;
-  if (len==undefined && chk.checked==1) 
+  if (len==undefined && chk.checked==1)
   {
     if(!str)
       str = chk.value;
-    else  
+    else
     str = "#"+chk.value;
   }
   else
@@ -56,7 +56,7 @@
     {
      if(!str)
       str = chk[pr].value;
-     else 
+     else
       str = str+"#"+chk[pr].value;
     }
    }
@@ -67,16 +67,16 @@
    alert("<?php echo xl('The destination form was closed')?>");
   else
    opener.set_related(str,"drugs");
-   
+
   window.close();
-  
- }
- 
+
+ }
+
 function window_close(chk)
 {
  window.close();
 }
- 
+
 function chkbox_select_none(chk)
 {
  var len=chk.length;
@@ -112,8 +112,8 @@
   return false;
  }
  top.restoreSession();
- return true; 
-}   
+ return true;
+}
 
 </script>
 </head>
@@ -133,7 +133,7 @@
    <input type='text' name='search_term' id='search_term' size='12' value='<?php echo $_REQUEST['search_term']; ?>'
     title='<?php xl('Any part of the drug id or drug name', 'e'); ?>' />
    &nbsp;
-   <input type='submit' name='bn_search' id='bn_search' value='<?php xl('Search', 'e'); ?>' />  
+   <input type='submit' name='bn_search' id='bn_search' value='<?php xl('Search', 'e'); ?>' />
    </b>
   </td>
  </tr>
@@ -152,9 +152,9 @@
     $search_term = $_REQUEST['search_term'];
     {
     $query = "SELECT count(*) as count FROM drugs " .
-      "WHERE (drug_id LIKE '%$search_term%' OR " .
-      "name LIKE '%$search_term%') ";
-    $res = sqlStatement($query);
+      "WHERE (drug_id LIKE ? OR " .
+      "name LIKE ?) ";
+    $res = sqlStatement($query, array('%'.$search_term.'%', '%'.$search_term.'%'));
     if ($row = sqlFetchArray($res)) {
         $no_of_items = addslashes($row['count']);
         if ($no_of_items < 1) {
@@ -165,15 +165,15 @@
             echo xl('Please enter new search string');?>");
         document.theform.search_term.value=" ";
         document.theform.search_term.focus();
-        </script>    
+        </script>
         <?php
         }
 
         $query = "SELECT drug_id, name FROM drugs " .
-        "WHERE (drug_id LIKE '%$search_term%' OR " .
-        "name LIKE '%$search_term%') " .
+        "WHERE (drug_id LIKE ? OR " .
+        "name LIKE ?) " .
         "ORDER BY drug_id";
-        $res = sqlStatement($query);
+        $res = sqlStatement($query, array('%'.$search_term.'%', '%'.$search_term.'%'));
         $row_count = 0;
         while ($row = sqlFetchArray($res)) {
               $row_count = $row_count + 1;
@@ -191,13 +191,13 @@
  </table>
 <center>
  <input type='button' name='select_all' value='<?php xl('Select All', 'e'); ?>' onclick="chkbox_select_all(document.select_drug.chkbox);"/>
- 
+
  <input type='button' name='unselect_all' value='<?php xl('Unselect All', 'e'); ?>' onclick="chkbox_select_none(document.select_drug.chkbox);"/>
- 
+
  <input type='button' name='submit' value='<?php xl('Submit', 'e'); ?>' onclick="window_submit(document.select_drug.chkbox);"/>
- 
+
  <input type='button' name='cancel' value='<?php xl('Cancel', 'e'); ?>' onclick="window_close();"/>
-</center> 
+</center>
 <?php } ?>
 </form>
 </body>
```
