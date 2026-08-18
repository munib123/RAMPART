# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 80-120 of the vulnerable file.

	}

	require_once "@CENTREON_ETC@/centreon.conf.php";
	require_once "$centreon_path/www/class/centreonGMT.class.php";
	require_once "$centreon_path/www/class/centreonDB.class.php";

	/*
	 * Connect DB
	 */
	$pearDB = new CentreonDB();
	$pearDBO = new CentreonDB("centstorage");

	/*
	 * Init GMT Class
	 */
	$CentreonGMT = new CentreonGMT($pearDB);

	/*
	 * Check Session activity
	 */
	$session = $pearDB->query("SELECT * FROM `session` WHERE session_id = '".$_GET["session_id"]."'");
	if (!$session->numRows()){
		;
	} else {

	 	/*
	 	 * Get GMT for current user
	 	 */
	 	$gmt = $CentreonGMT->getMyGMTFromSession($_GET["session_id"], $pearDB);

		/*
		 * Get RRDTool binary Path
		 */
		$DBRESULT = $pearDB->query("SELECT * FROM `options`");
		while ($option = $DBRESULT->fetchRow()) {
			$optGen[$option["key"]] = $option["value"];
			if ($option["key"] == 'rrdtool_path_bin') {
				$rrdtoolPath = $option["value"];
			}
		}
		$DBRESULT->free();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,7 +97,7 @@
 	/*
 	 * Check Session activity
 	 */
-	$session = $pearDB->query("SELECT * FROM `session` WHERE session_id = '".$_GET["session_id"]."'");
+    $session = $pearDB->query("SELECT * FROM `session` WHERE session_id = '".$pearDB->escape($_GET["session_id"])."'");
 	if (!$session->numRows()){
 		;
 	} else {
```
