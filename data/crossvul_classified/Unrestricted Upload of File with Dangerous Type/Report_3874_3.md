# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 3874_3
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3874_3`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
/*
 * frmcontactrange.php
 * calcule le code html de la partie intervalle du formulaire de contact
 * Ce script fait partie de l'application GRR
 * Dernière modification : $Date: 2020-01-17 14:30$
 * @author    JeromeB & Yan Naessens
 * @copyright Copyright 2003-2020 Team DEVOME - JeromeB
 * @link      http://www.gnu.org/licenses/licenses.html
 *
 * This file is part of GRR.
 *
 * GRR is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
 
include "include/connect.inc.php";
include "include/mysql.inc.php";
include "include/misc.inc.php";
include "include/functions.inc.php";

$id = $_GET['id'];
$query = "SELECT access,morningstarts_area,eveningends_area,eveningends_minutes_area,enable_periods,resolution_area FROM ".TABLE_PREFIX."_area
    WHERE id = '".$id."' ";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
  * frmcontactrange.php
  * calcule le code html de la partie intervalle du formulaire de contact
  * Ce script fait partie de l'application GRR
- * Dernière modification : $Date: 2020-01-17 14:30$
+ * Dernière modification : $Date: 2020-03-13 11:00$
  * @author    JeromeB & Yan Naessens
  * @copyright Copyright 2003-2020 Team DEVOME - JeromeB
  * @link      http://www.gnu.org/licenses/licenses.html
@@ -22,8 +22,10 @@
 include "include/functions.inc.php";
 
 $id = $_GET['id'];
+if ($id != protect_data_sql($id))
+    die('Donnée incorrecte');
 $query = "SELECT access,morningstarts_area,eveningends_area,eveningends_minutes_area,enable_periods,resolution_area FROM ".TABLE_PREFIX."_area
-    WHERE id = '".$id."' ";
+    WHERE id = '".protect_data_sql($id)."' ";
 // echo $query."<br />";
 $res = grr_sql_query($query);
 $val= grr_sql_row($res,0);
```
