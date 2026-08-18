# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3816_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3816_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 36-73 of the vulnerable file.

 *
 */

    ini_set("display_errors", "Off");

	require_once "@CENTREON_ETC@/centreon.conf.php";
	require_once $centreon_path . "www/class/centreonSession.class.php";
	require_once $centreon_path . "www/class/centreon.class.php";
	require_once $centreon_path . "www/class/centreonDB.class.php";
	require_once $centreon_path . "www/class/centreonXML.class.php";
	require_once $centreon_path . "www/class/centreonGMT.class.php";

	$pearDB = new CentreonDB();
	$buffer = new CentreonXML();
	$buffer->startElement("entry");

	session_start();
	if (isset($_SESSION['centreon'])) {
	    $oreon = $_SESSION['centreon'];
    	$currentTime = $oreon->CentreonGMT->getDate(_("Y/m/d G:i"), time(), $oreon->user->getMyGMT());
    	$DBRESULT = $pearDB->query("SELECT user_id FROM session WHERE session_id = '" . htmlentities($_GET['sid'], ENT_QUOTES, "UTF-8") . "'");
    	if ($DBRESULT->numRows()) {
    		$buffer->writeElement("state", "ok");
    	} else {
    		$buffer->writeElement("state", "nok");
    	}
	} else {
        $currentTime = date(_("Y/m/d G:i"));
	    $buffer->writeElement("state", "nok");
	}
	$buffer->writeElement("time", $currentTime);
	$buffer->endElement();
	header('Content-Type: text/xml');
	header('Pragma: no-cache');
	header('Expires: 0');
	header('Cache-Control: no-cache, must-revalidate');
	$buffer->output();
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,7 @@
 	if (isset($_SESSION['centreon'])) {
 	    $oreon = $_SESSION['centreon'];
     	$currentTime = $oreon->CentreonGMT->getDate(_("Y/m/d G:i"), time(), $oreon->user->getMyGMT());
-    	$DBRESULT = $pearDB->query("SELECT user_id FROM session WHERE session_id = '" . htmlentities($_GET['sid'], ENT_QUOTES, "UTF-8") . "'");
+    	$DBRESULT = $pearDB->query("SELECT user_id FROM session WHERE session_id = '" . $pearDB->escape($_GET['sid']) . "'");
     	if ($DBRESULT->numRows()) {
     		$buffer->writeElement("state", "ok");
     	} else {
```
