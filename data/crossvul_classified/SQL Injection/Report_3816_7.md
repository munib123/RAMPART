# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3816_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3816_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 43-83 of the vulnerable file.

	require_once $centreon_path."/www/class/centreonDB.class.php";
	require_once $centreon_path."/www/class/centreonXML.class.php";
	require_once $centreon_path."/www/class/centreonACL.class.php";
	require_once $centreon_path."/www/class/centreon.class.php";
	require_once $centreon_path."/www/class/centreonSession.class.php";
	require_once $centreon_path."/www/class/centreonLang.class.php";
	require_once $centreon_path."/www/class/centreonMenu.class.php";

	if (!isset($_GET["sid"]) || !isset($_GET["menu"]))
		exit();

	/*
	 * Create MySQL connector
	 */
	$pearDB = new CentreonDB();
	global $pearDB;

	/*
	 * Check Session existence
	 */
	$session = $pearDB->query("SELECT user_id FROM `session` WHERE session_id = '".htmlentities($_GET["sid"], ENT_QUOTES, "UTF-8")."'");
	if (!$session->numRows()){
		$buffer = new CentreonXML();
		$buffer->startElement("root");
		$buffer->endElement();
		header('Content-Type: text/xml');
		header('Cache-Control: no-cache');
		$buffer->output();
		exit;
	}

	session_start();
	$oreon = $_SESSION['centreon'];

	$centreonLang = new CentreonLang($centreon_path, $oreon);
	$centreonLang->bindLang();
    $centreonMenu = new CentreonMenu($centreonLang);

	/*
	 * Init XML class
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,7 +60,7 @@
 	/*
 	 * Check Session existence
 	 */
-	$session = $pearDB->query("SELECT user_id FROM `session` WHERE session_id = '".htmlentities($_GET["sid"], ENT_QUOTES, "UTF-8")."'");
+	$session = $pearDB->query("SELECT user_id FROM `session` WHERE session_id = '".$pearDB->escape($_GET["sid"])."'");
 	if (!$session->numRows()){
 		$buffer = new CentreonXML();
 		$buffer->startElement("root");
@@ -95,7 +95,7 @@
 	/*
 	 * Get CSS
 	 */
-	$DBRESULT2 = $pearDB->query("SELECT css_name FROM `css_color_menu` WHERE menu_nb = '".htmlentities($_GET["menu"], ENT_QUOTES, "UTF-8")."' LIMIT 1");
+	$DBRESULT2 = $pearDB->query("SELECT css_name FROM `css_color_menu` WHERE menu_nb = '".$pearDB->escape($_GET["menu"])."' LIMIT 1");
 	$menu_style = $DBRESULT2->fetchRow();
 
 	ob_start();
```
