# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3816_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3816_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 34-74 of the vulnerable file.

 * SVN : $URL$
 * SVN : $Id$
 * 
 */
 
	
	require_once "@CENTREON_ETC@/centreon.conf.php";
	
	require_once $centreon_path."www/include/reporting/dashboard/common-Func.php";
	require_once $centreon_path."www/class/centreonDuration.class.php";
	require_once $centreon_path."www/class/centreonXML.class.php";
	require_once $centreon_path."www/class/centreonDB.class.php";
	require_once $centreon_path."www/include/reporting/dashboard/xmlInformations/common-Func.php";
		
	$buffer = new CentreonXML();
	$buffer->startElement("data");	

	$pearDB 	= new CentreonDB();
	$pearDBO 	= new CentreonDB("centstorage");

	$DBRESULT = $pearDB->query("SELECT * FROM session WHERE session_id = '" . htmlentities($_GET['session'], ENT_QUOTES, "UTF-8") . "'");
	if (!$DBRESULT->numRows())
		exit();
	

	/*
	 * Definition of status
	 */
	$state 		= array("UP" => _("UP"), "DOWN" => _("DOWN"), "UNREACHABLE" => _("UNREACHABLE"), "UNDETERMINED" => _("UNDETERMINED"));
	$statesTab 	= array("UP", "DOWN", "UNREACHABLE");
	
	$buffer = new CentreonXML();
	$buffer->startElement("data");	
	
	if (isset($_GET["id"]) && isset($_GET["color"])){
		
		$color = array();
		foreach ($_GET["color"] as $key => $value) {
			$color[$key] = htmlentities($value, ENT_QUOTES, "UTF-8");
		}
		
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
 	$pearDB 	= new CentreonDB();
 	$pearDBO 	= new CentreonDB("centstorage");
 
-	$DBRESULT = $pearDB->query("SELECT * FROM session WHERE session_id = '" . htmlentities($_GET['session'], ENT_QUOTES, "UTF-8") . "'");
+	$DBRESULT = $pearDB->query("SELECT * FROM session WHERE session_id = '" . $pearDB->escape($_GET['session']) . "'");
 	if (!$DBRESULT->numRows())
 		exit();
 	
```
