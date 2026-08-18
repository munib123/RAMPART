# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3816_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3816_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 34-70 of the vulnerable file.

 * SVN : $URL$
 * SVN : $Id$
 * 
 */
 
	require_once "@CENTREON_ETC@/centreon.conf.php";
	require_once $centreon_path."/www/class/centreonDB.class.php";
	require_once $centreon_path."/www/class/centreon.class.php";
	require_once $centreon_path."/www/class/centreonSession.class.php";
	
	session_start();
	if(!isset($_SESSION['centreon']) || !isset($_GET['div']) || !isset($_GET['uid']))
		exit();
	$oreon = $_SESSION['centreon'];	
	 
	$pearDB = new CentreonDB();
	
	/*
	 * Check session id
	 */
	$session = $pearDB->query("SELECT user_id FROM `session` WHERE session_id = '".htmlentities(session_id(), ENT_QUOTES, "UTF-8")."' AND user_id = '".htmlentities($_GET['uid'], ENT_QUOTES, "UTF-8")."'");
	if (!$session->numRows()){
		exit;
	}
	
	if (isset($_GET['div']) && isset($_GET['uid'])) {
		
		$my_div = htmlentities($_GET['div'], ENT_QUOTES, "UTF-8");
		$my_uid = htmlentities($_GET['uid'], ENT_QUOTES, "UTF-8");
		
		if (!isset($_SESSION['_Div_' . $my_div]) || $_SESSION['_Div_' . $my_div] == 1) {
			$_SESSION['_Div_' . $my_div] = 0; 
		} else {
			$_SESSION['_Div_' . $my_div] = 1;
		}
	}
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
 	/*
 	 * Check session id
 	 */
-	$session = $pearDB->query("SELECT user_id FROM `session` WHERE session_id = '".htmlentities(session_id(), ENT_QUOTES, "UTF-8")."' AND user_id = '".htmlentities($_GET['uid'], ENT_QUOTES, "UTF-8")."'");
+	$session = $pearDB->query("SELECT user_id FROM `session` WHERE session_id = '".$pearDB->escape(session_id())."' AND user_id = '".$pearDB->escape($_GET['uid'])."'");
 	if (!$session->numRows()){
 		exit;
 	}
```
