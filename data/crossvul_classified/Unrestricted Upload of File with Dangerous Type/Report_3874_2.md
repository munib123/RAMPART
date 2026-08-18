# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 3874_2
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3874_2`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
/**
 * frmcontactlist.php
 * calcule la liste des ressources visibles dans un domaine
 * Ce script fait partie de l'application GRR
 * Dernière modification : $Date: 2018-07-31 16:00$
 * @author    JeromeB & Yan Naessens
 * @copyright Copyright 2003-2018 Team DEVOME - JeromeB
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
// echo "<optgroup label=\"Salles\">"; je supprime optgroup car les ressources ne sont pas toujours des salles ! YN
$res = grr_sql_query("SELECT room_name,id FROM ".TABLE_PREFIX."_room WHERE area_id = '".$id."' ORDER BY room_name");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,9 +3,9 @@
  * frmcontactlist.php
  * calcule la liste des ressources visibles dans un domaine
  * Ce script fait partie de l'application GRR
- * Dernière modification : $Date: 2018-07-31 16:00$
+ * Dernière modification : $Date: 2020-03-13 11:00$
  * @author    JeromeB & Yan Naessens
- * @copyright Copyright 2003-2018 Team DEVOME - JeromeB
+ * @copyright Copyright 2003-2020 Team DEVOME - JeromeB
  * @link      http://www.gnu.org/licenses/licenses.html
  *
  * This file is part of GRR.
@@ -22,8 +22,9 @@
 include "include/functions.inc.php";
 
 $id = $_GET['id'];
-// echo "<optgroup label=\"Salles\">"; je supprime optgroup car les ressources ne sont pas toujours des salles ! YN
-$res = grr_sql_query("SELECT room_name,id FROM ".TABLE_PREFIX."_room WHERE area_id = '".$id."' ORDER BY room_name");
+if ($id != protect_data_sql($id))
+    die('Donnée incorrecte');
+$res = grr_sql_query("SELECT room_name,id FROM ".TABLE_PREFIX."_room WHERE area_id = '".protect_data_sql($id)."' ORDER BY room_name");
 $nbresult = mysqli_num_rows($res);
 $user_name = getUserName();
 if ($nbresult != 0)
```
