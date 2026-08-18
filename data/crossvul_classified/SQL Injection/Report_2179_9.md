# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_9
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_9`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 154-194 of the vulnerable file.

		} else {
			$query = "SELECT sg_id FROM `servicegroup`";
		}
		$DBRES = $pearDB->query($query);
		while ($row = $DBRES->fetchRow()) {
			$tab[$row['sg_id']] = 1;
		}
		return $tab;
	}

	/*
	 * if debug == 0 => Normal,
	 * debug == 1 => get use,
	 * debug == 2 => log in file (log.xml)
	 */

	global $is_admin, $user_id;

	$is_admin = isUserAdmin($_GET["sid"]);
	if (isset($_GET["sid"]) && $_GET["sid"]) {
		$DBRESULT = $pearDB->query("SELECT user_id FROM session where session_id = '".$_GET["sid"]."'");
		$session = $DBRESULT->fetchRow();
		$access = new CentreonAcl($session["user_id"], $is_admin);
		$lca = array("LcaHost" => $access->getHostServices(($oreon->broker->getBroker() == "ndo" ? $pearDBndo : $pearDBO)), "LcaHostGroup" => $access->getHostGroups(), "LcaSG" => $access->getServiceGroups());
		$hoststr = $access->getHostsString("ID", ($oreon->broker->getBroker() == "ndo" ? $pearDBndo : $pearDBO));
		$servicestr = $access->getServicesString("ID", ($oreon->broker->getBroker() == "ndo" ? $pearDBndo : $pearDBO));
	} else {
		exit();
	}

	$normal_mode = 1;
	(isset($_GET["mode"])) ? $normal_mode = htmlentities($_GET["mode"], ENT_QUOTES, "UTF-8") : $normal_mode = 1;
	(isset($_GET["id"])) ? $url_var = htmlentities($_GET["id"], ENT_QUOTES, "UTF-8") : $url_var = 0;
	(isset($_GET["search_host"])) ? $search_host = $_GET["search_host"] : $search_host = "";
	(isset($_GET["search_service"])) ? $search_service = $_GET["search_service"] : $search_service = "";
	(isset($_GET["lock_tree"])) ? $lockTree = $_GET['lock_tree'] : $lockTree = 0;

	/*
	 * Create hostCahe
	 */
	$hostCache = array();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,7 +171,7 @@
 
 	$is_admin = isUserAdmin($_GET["sid"]);
 	if (isset($_GET["sid"]) && $_GET["sid"]) {
-		$DBRESULT = $pearDB->query("SELECT user_id FROM session where session_id = '".$_GET["sid"]."'");
+		$DBRESULT = $pearDB->query("SELECT user_id FROM session where session_id = '".$pearDB->escape($_GET["sid"])."'");
 		$session = $DBRESULT->fetchRow();
 		$access = new CentreonAcl($session["user_id"], $is_admin);
 		$lca = array("LcaHost" => $access->getHostServices(($oreon->broker->getBroker() == "ndo" ? $pearDBndo : $pearDBO)), "LcaHostGroup" => $access->getHostGroups(), "LcaSG" => $access->getServiceGroups());
```
