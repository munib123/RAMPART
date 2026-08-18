# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.

 * combined work based on this program. Thus, the terms and conditions of the GNU
 * General Public License cover the whole combination.
 *
 * As a special exception, the copyright holders of this program give MERETHIS
 * permission to link this program with independent modules to produce an executable,
 * regardless of the license terms of these independent modules, and to copy and
 * distribute the resulting executable under terms of MERETHIS choice, provided that
 * MERETHIS also meet, for each linked independent module, the terms  and conditions
 * of the license of that module. An independent module is a module which is not
 * derived from this program. If you modify this program, you may extend this
 * exception to your version of the program, but you are not obliged to do so. If you
 * do not wish to do so, delete this exception statement from your version.
 *
 * For more information : contact@centreon.com
 *
 * SVN : $URL$
 * SVN : $Id$
 *
 */

	include_once("@CENTREON_ETC@/centreon.conf.php");

	require_once $centreon_path . "/www/class/centreonDB.class.php";
	require_once $centreon_path . "/www/class/centreonXML.class.php";

	/** ************************************
	 * start init db
	 */
	$pearDB = new CentreonDB();

	/** ************************************
	 * start XML Flow
	 */
	$buffer = new CentreonXML();
	$buffer->startElement("traps");

	$empty = 0;
	if (isset($_POST["mnftr_id"])){
		$traps = array();
		if ($_POST["mnftr_id"] == -1) {
			$DBRESULT = $pearDB->query("SELECT traps_id, traps_name FROM traps ORDER BY traps_name");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,46 +36,48 @@
  *
  */
 
-	include_once("@CENTREON_ETC@/centreon.conf.php");
+include_once("@CENTREON_ETC@/centreon.conf.php");
 
-	require_once $centreon_path . "/www/class/centreonDB.class.php";
-	require_once $centreon_path . "/www/class/centreonXML.class.php";
+require_once $centreon_path . "/www/class/centreonDB.class.php";
+require_once $centreon_path . "/www/class/centreonXML.class.php";
 
-	/** ************************************
-	 * start init db
-	 */
-	$pearDB = new CentreonDB();
+/** ************************************
+ * start init db
+ */
+$pearDB = new CentreonDB();
 
-	/** ************************************
-	 * start XML Flow
-	 */
-	$buffer = new CentreonXML();
-	$buffer->startElement("traps");
+/** ************************************
+ * start XML Flow
+ */
+$buffer = new CentreonXML();
+$buffer->startElement("traps");
 
-	$empty = 0;
-	if (isset($_POST["mnftr_id"])){
-		$traps = array();
-		if ($_POST["mnftr_id"] == -1) {
-			$DBRESULT = $pearDB->query("SELECT traps_id, traps_name FROM traps ORDER BY traps_name");
-		} else if ($_POST["mnftr_id"] == -2) {
-			$empty = 1;
-		} else if ($_POST["mnftr_id"] != 0) {
-			$DBRESULT = $pearDB->query("SELECT traps_id, traps_name FROM traps WHERE manufacturer_id = " . $_POST["mnftr_id"]. " ORDER BY traps_name");
-		}
+$mnftr_id = $pearDB->escape($_POST["mnftr_id"]);
 
-		if ($empty != 1) {
-			while ($trap = $DBRESULT->fetchRow()){
-				$buffer->startElement("trap");
-				$buffer->writeElement("id", $trap["traps_id"]);
-				$buffer->writeElement("name", $trap["traps_name"]);
-				$buffer->endElement();
-			}
-			$DBRESULT->free();
-		}
-	} else {
-		$buffer->writeElement("error", "mnftr_id not found");
-	}
-	$buffer->endElement();
-	header('Content-Type: text/xml');
-	$buffer->output();
-?>
+$empty = 0;
+if (isset($_POST["mnftr_id"])){
+    $traps = array();
+    if ($_POST["mnftr_id"] == -1) {
+        $DBRESULT = $pearDB->query("SELECT traps_id, traps_name FROM traps ORDER BY traps_name");
+    } else if ($_POST["mnftr_id"] == -2) {
+        $empty = 1;
+    } else if ($_POST["mnftr_id"] != 0) {
+        $DBRESULT = $pearDB->query("SELECT traps_id, traps_name FROM traps WHERE manufacturer_id = " . $mnftr_id . " ORDER BY traps_name");
+    }
+
+    if ($empty != 1) {
+        while ($trap = $DBRESULT->fetchRow()){
+            $buffer->startElement("trap");
+            $buffer->writeElement("id", $trap["traps_id"]);
+            $buffer->writeElement("name", $trap["traps_name"]);
+            $buffer->endElement();
+        }
+        $DBRESULT->free();
+    }
+} else {
+    $buffer->writeElement("error", "mnftr_id not found");
+}
+$buffer->endElement();
+
+header('Content-Type: text/xml');
+$buffer->output();
```
