# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 97_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `97_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-38 of the vulnerable file.

<?php
/********************************************************************************\
 * Copyright (C) ViCarePlus, Visolve (vicareplus_engg@visolve.com)              *
 *                                                                              *
 * This program is free software; you can redistribute it and/or                *
 * modify it under the terms of the GNU General Public License                  *
 * as published by the Free Software Foundation; either version 2               *
 * of the License, or (at your option) any later version.                       *
 *                                                                              *
 * This program is distributed in the hope that it will be useful,              *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of               *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                *
 * GNU General Public License for more details.                                 *
 *                                                                              *
 * You should have received a copy of the GNU General Public License            *
 * along with this program; if not, write to the Free Software                  *
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.  *
 \********************************************************************************/
require_once("../globals.php");
require_once("$srcdir/patient.inc");
require_once("../../custom/code_types.inc.php");

$info_msg = "";
$codetype = $_REQUEST['codetype'];
$form_code_type = $_POST['form_code_type'];
?>
<html>
<head>
<?php html_header_show(); ?>
<title><?php xl('Code Finder', 'e'); ?></title>
<link rel="stylesheet" href='<?php echo $css_header ?>' type='text/css'>

<style>
td { font-size:10pt; }
</style>

<script language="JavaScript">
//pass value selected to the parent window
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,21 +1,17 @@
 <?php
-/********************************************************************************\
- * Copyright (C) ViCarePlus, Visolve (vicareplus_engg@visolve.com)              *
- *                                                                              *
- * This program is free software; you can redistribute it and/or                *
- * modify it under the terms of the GNU General Public License                  *
- * as published by the Free Software Foundation; either version 2               *
- * of the License, or (at your option) any later version.                       *
- *                                                                              *
- * This program is distributed in the hope that it will be useful,              *
- * but WITHOUT ANY WARRANTY; without even the implied warranty of               *
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                *
- * GNU General Public License for more details.                                 *
- *                                                                              *
- * You should have received a copy of the GNU General Public License            *
- * along with this program; if not, write to the Free Software                  *
- * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.  *
- \********************************************************************************/
+/**
+ * find_code_popup.php
+ *
+ * @package   OpenEMR
+ * @link      http://www.open-emr.org
+ * @author    Visolve <vicareplus_engg@visolve.com>
+ * @author    Brady Miller <brady.g.miller@gmail.com>
+ * @copyright Copyright (c) ViCarePlus, Visolve <vicareplus_engg@visolve.com>
+ * @copyright Copyright (c) 2018 Brady Miller <brady.g.miller@gmail.com>
+ * @license   https://github.com/openemr/openemr/blob/master/LICENSE GNU General Public License 3
+ */
+
+
 require_once("../globals.php");
 require_once("$srcdir/patient.inc");
 require_once("../../custom/code_types.inc.php");
@@ -37,14 +33,14 @@
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
@@ -55,7 +51,7 @@
     {
      if(!str)
       str = chk[pr].value;
-     else 
+     else
       str = str+"#"+chk[pr].value;
     }
    }
@@ -66,16 +62,16 @@
    alert("<?php echo xl('The destination form was closed');?>");
   else
    opener.set_related(str,"diagnosis");
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
@@ -111,7 +107,7 @@
   return false;
  }
  top.restoreSession();
- return true; 
+ return true;
 }
 
 </script>
@@ -130,7 +126,7 @@
    <b>
 <?php
 if ($codetype) {
-    echo "<input type='text' name='form_code_type' value='$codetype' size='5' readonly>\n";
+    echo "<input type='text' name='form_code_type' value='" . attr($codetype) . "' size='5' readonly>\n";
 } else {
     echo "   <select name='form_code_type'";
     echo ">\n";
@@ -153,10 +149,10 @@
 }
 ?>
     <?php xl('Search for', 'e'); ?>
-   <input type='text' name='search_term' id='search_term' size='12' value='<?php echo $_REQUEST['search_term']; ?>'
+   <input type='text' name='search_term' id='search_term' size='12' value='<?php echo attr($_REQUEST['search_term']); ?>'
     title='<?php xl('Any part of the desired code or its description', 'e'); ?>' />
-   &nbsp;  
-   <input type='submit' name='bn_search' id='bn_search' value='<?php xl('Search', 'e'); ?>' />   
+   &nbsp;
+   <input type='submit' name='bn_search' id='bn_search' value='<?php xl('Search', 'e'); ?>' />
    </b>
   </td>
  </tr>
@@ -187,7 +183,7 @@
             $drug_id = addslashes($row['drug_id']);
             $selector = addslashes($row['selector']);
             $desc = addslashes($row['name']);
-            ?>    
+            ?>
              <input type="checkbox" name="diagnosis[row_count]" value= "<?php echo $desc; ?>" > <?php echo $drug_id."    ".$selector."     ".$desc."</br>";
         }
     } else {
@@ -205,7 +201,7 @@
             echo xl('Please enter new search string');?>");
           document.theform.search_term.value=" ";
              document.theform.search_term.focus();
-             </script>    
+             </script>
                 <?php
             }
 
@@ -232,14 +228,14 @@
 <center>
 </br>
  <input type='button' id='select_all' value='<?php xl('Select All', 'e'); ?>' onclick="chkbox_select_all(document.select_diagonsis.chkbox);"/>
- 
+
  <input type='button' id='unselect_all' value='<?php xl('Unselect All', 'e'); ?>' onclick="chkbox_select_none(document.select_diagonsis.chkbox);"/>
- 
+
  <input type='button' id='submit' value='<?php xl('Submit', 'e'); ?>' onclick="window_submit(document.select_diagonsis.chkbox);"/>
- 
+
  <input type='button' id='cancel' value='<?php xl('Cancel', 'e'); ?>' onclick="window_close();"/>
- 
-</center> 
+
+</center>
 <?php } ?>
 </form>
 </body>
```
