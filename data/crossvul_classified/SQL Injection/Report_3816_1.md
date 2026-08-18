# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3816_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3816_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 38-65 of the vulnerable file.

	# return argument for specific command in txt format
	# use by ajax

	require_once("@CENTREON_ETC@/centreon.conf.php");
	require_once($centreon_path."www/class/centreonDB.class.php");

	function myDecodeService($arg)	{
		$arg = str_replace('#BR#', "\\n", $arg);
		$arg = str_replace('#T#', "\\t", $arg);
		$arg = str_replace('#R#', "\\r", $arg);
		$arg = str_replace('#S#', "/", $arg);
		$arg = str_replace('#BS#', "\\", $arg);
		return html_entity_decode($arg, ENT_QUOTES, "UTF-8");
	}

	header('Content-type: text/html; charset=utf-8');

	$pearDB = new CentreonDB();

	if (isset($_POST["index"])){
		$DBRESULT = $pearDB->query("SELECT `command_example` FROM `command` WHERE `command_id` = '". $_POST["index"] ."'");
		while ($arg = $DBRESULT->fetchRow())
			echo myDecodeService($arg["command_example"]);
		unset($arg);
		unset($DBRESULT);
		$pearDB->disconnect();
	}
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,7 +55,7 @@
 	$pearDB = new CentreonDB();
 
 	if (isset($_POST["index"])){
-		$DBRESULT = $pearDB->query("SELECT `command_example` FROM `command` WHERE `command_id` = '". $_POST["index"] ."'");
+		$DBRESULT = $pearDB->query("SELECT `command_example` FROM `command` WHERE `command_id` = '". $pearDB->escape($_POST["index"]) ."'");
 		while ($arg = $DBRESULT->fetchRow())
 			echo myDecodeService($arg["command_example"]);
 		unset($arg);
```
