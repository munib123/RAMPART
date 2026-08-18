# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1348_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1348_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
/** 
 * TestLink Open Source Project - http://testlink.sourceforge.net/
 * This script is distributed under the GNU General Public License 2 or later. 
 *
 * @package		TestLink
 * @author		Andreas Simon
 * @copyright	2005-2010, TestLink community 
 * @version		CVS: $Id: tc_exec_unassign_all.php,v 1.3 2010/07/26 19:00:57 asimon83 Exp $
 * @link		http://www.teamst.org/index.php
 *
 * @internal revisions:
 * 
 */

require_once(dirname(__FILE__)."/../../config.inc.php");
require_once("common.php");

testlinkInitPage($db, false, false, "checkRights");

$assignment_mgr = new assignment_mgr($db);
$testplan_mgr = new testplan($db);
$build_mgr = new build_mgr($db);
$templateCfg = templateConfiguration();

$args = init_args();
$gui = init_gui($db, $args);

$assignment_count = 0;

$build_name = "";
if ($args->build_id) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,12 +4,7 @@
  * This script is distributed under the GNU General Public License 2 or later. 
  *
  * @package		TestLink
- * @author		Andreas Simon
- * @copyright	2005-2010, TestLink community 
- * @version		CVS: $Id: tc_exec_unassign_all.php,v 1.3 2010/07/26 19:00:57 asimon83 Exp $
- * @link		http://www.teamst.org/index.php
- *
- * @internal revisions:
+ * @copyright	2005-2019, TestLink community 
  * 
  */
 
@@ -69,11 +64,12 @@
 	
 	$_REQUEST = strings_stripSlashes($_REQUEST);
 	
-	$args->build_id = isset($_REQUEST['build_id']) ? $_REQUEST['build_id'] : 0;
+	$args->build_id = isset($_REQUEST['build_id']) ? 
+	                  intval($_REQUEST['build_id']) : 0;
 	$args->confirmed = isset($_REQUEST['confirmed']) && $_REQUEST['confirmed'] == 'yes' ? true : false;
 	
 	$args->user_id = $_SESSION['userID'];
-	$args->testproject_id = $_SESSION['testprojectID'];
+	$args->testproject_id = intval($_SESSION['testprojectID']);
 	$args->testproject_name = $_SESSION['testprojectName'];
 	
 	$args->refreshTree = isset($_SESSION['setting_refresh_tree_on_action']) ?
```
