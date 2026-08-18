# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 117-157 of the vulnerable file.

		foreach($sc_arr as $key=>$value)	{
			$DBRESULT = $pearDB->query("UPDATE service_categories SET sc_activate = '1' WHERE sc_id = '".$key."'");
		}
	}

	function disableServiceCategorieInDB($sc_id = null, $sc_arr = array())	{
		if (!$sc_id && !count($sc_arr)) return;
		global $pearDB;
		if ($sc_id)
			$sc_arr = array($sc_id=>"1");
		foreach($sc_arr as $key=>$value)	{
			$DBRESULT = $pearDB->query("UPDATE service_categories SET sc_activate = '0' WHERE sc_id = '".$key."'");
		}
	}

	function insertServiceCategorieInDB(){
		global $pearDB, $centreon;

		if (testServiceCategorieExistence($_POST["sc_name"])){
                $DBRESULT = $pearDB->query("INSERT INTO `service_categories` (`sc_name`, `sc_description`, `level`, `icon_id`, `sc_activate` ) 
                    VALUES ('".$_POST["sc_name"]."', '".$_POST["sc_description"]."', ".
                        (isset($_POST['sc_severity_level']) && $_POST['sc_type'] ? $pearDB->escape($_POST['sc_severity_level']):"NULL").", ".
                        (isset($_POST['sc_severity_icon']) && $_POST['sc_type'] ? $pearDB->escape($_POST['sc_severity_icon']) : "NULL").", ".
                        "'".$_POST["sc_activate"]["sc_activate"]."')");
                $DBRESULT = $pearDB->query("SELECT MAX(sc_id) FROM `service_categories` WHERE sc_name LIKE '".$_POST["sc_name"]."'");
                $data = $DBRESULT->fetchRow();
        }
        updateServiceCategoriesServices($data["MAX(sc_id)"]);
        $centreon->user->access->updateACL();
	}

	function updateServiceCategorieInDB(){
		global $pearDB, $centreon;

		$DBRESULT = $pearDB->query("UPDATE `service_categories` SET 
                    `sc_name` = '".$_POST["sc_name"]."' , 
                    `sc_description` = '".$_POST["sc_description"]."' , 
                    `level` = ".(isset($_POST['sc_severity_level']) && $_POST['sc_type'] ? $pearDB->escape($_POST['sc_severity_level']):"NULL").", 
                    `icon_id` = ".(isset($_POST['sc_severity_icon']) && $_POST['sc_type'] ? $pearDB->escape($_POST['sc_severity_icon']) : "NULL").",
                    `sc_activate` = '".$_POST["sc_activate"]["sc_activate"]."' 
                    WHERE `sc_id` = '".$_POST["sc_id"]."'");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,11 +134,11 @@
 
 		if (testServiceCategorieExistence($_POST["sc_name"])){
                 $DBRESULT = $pearDB->query("INSERT INTO `service_categories` (`sc_name`, `sc_description`, `level`, `icon_id`, `sc_activate` ) 
-                    VALUES ('".$_POST["sc_name"]."', '".$_POST["sc_description"]."', ".
+                    VALUES ('".$pearDB->escape($_POST["sc_name"])."', '".$pearDB->escape($_POST["sc_description"])."', ".
                         (isset($_POST['sc_severity_level']) && $_POST['sc_type'] ? $pearDB->escape($_POST['sc_severity_level']):"NULL").", ".
                         (isset($_POST['sc_severity_icon']) && $_POST['sc_type'] ? $pearDB->escape($_POST['sc_severity_icon']) : "NULL").", ".
                         "'".$_POST["sc_activate"]["sc_activate"]."')");
-                $DBRESULT = $pearDB->query("SELECT MAX(sc_id) FROM `service_categories` WHERE sc_name LIKE '".$_POST["sc_name"]."'");
+                $DBRESULT = $pearDB->query("SELECT MAX(sc_id) FROM `service_categories` WHERE sc_name LIKE '".$pearDB->escape($_POST["sc_name"])."'");
                 $data = $DBRESULT->fetchRow();
         }
         updateServiceCategoriesServices($data["MAX(sc_id)"]);
```
