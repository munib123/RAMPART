# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2179_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2179_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.

 * exception to your version of the program, but you are not obliged to do so. If you
 * do not wish to do so, delete this exception statement from your version.
 * 
 * For more information : contact@centreon.com
 * 
 * SVN : $URL$
 * SVN : $Id$
 * 
 */
 
	if (!isset ($oreon))
		exit ();

	function testCommandCategorieExistence ($name = NULL)	{
		global $pearDB, $form;
		$id = NULL;
		
		if (isset($form))
			$id = $form->getSubmitValue('cmd_category_id');
		
		$DBRESULT = $pearDB->query("SELECT `category_name`, `cmd_category_id` FROM `command_categories` WHERE `category_name` = '".htmlentities($name, ENT_QUOTES, "UTF-8")."'");
		$cat = $DBRESULT->fetchRow();
		
		if ($DBRESULT->numRows() >= 1 && $cat["cmd_category_id"] == $id)
			return true;
		else if ($DBRESULT->numRows() >= 1 && $cat["cmd_category_id"] != $id)
			return false;
		else
			return true;
	}

	function multipleCommandCategorieInDB ($sc = array(), $nbrDup = array())	{
		global $pearDB;
			
		foreach ($sc as $key => $value)	{
			
			$DBRESULT = $pearDB->query("SELECT * FROM `command_categories` WHERE `cmd_category_id` = '".$key."' LIMIT 1");
			$row = $DBRESULT->fetchRow();
			$row["cmd_category_id"] = '';
			
			for ($i = 1; $i <= $nbrDup[$key]; $i++)	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,7 @@
 		if (isset($form))
 			$id = $form->getSubmitValue('cmd_category_id');
 		
-		$DBRESULT = $pearDB->query("SELECT `category_name`, `cmd_category_id` FROM `command_categories` WHERE `category_name` = '".htmlentities($name, ENT_QUOTES, "UTF-8")."'");
+		$DBRESULT = $pearDB->query("SELECT `category_name`, `cmd_category_id` FROM `command_categories` WHERE `category_name` = '".$pearDB->escape($name)."'");
 		$cat = $DBRESULT->fetchRow();
 		
 		if ($DBRESULT->numRows() >= 1 && $cat["cmd_category_id"] == $id)
@@ -88,14 +88,14 @@
 		global $pearDB;
 		
 		if (testCommandCategorieExistence($_POST["category_name"])){
-			$DBRESULT = $pearDB->query("INSERT INTO `command_categories` (`category_name` , `category_alias`, `category_order`) VALUES ('".$_POST["category_name"]."', '".$_POST["category_alias"]."', '1')");
+			$DBRESULT = $pearDB->query("INSERT INTO `command_categories` (`category_name` , `category_alias`, `category_order`) VALUES ('".$pearDB->escape($_POST["category_name"])."', '".$pearDB->escape($_POST["category_alias"])."', '1')");
 		}
 	}
 	
 	function updateCommandCategorieInDB(){
 		global $pearDB;
 		
-		$DBRESULT = $pearDB->query("UPDATE `command_categories` SET `category_name` = '".$_POST["category_name"]."' , `category_alias` = '".$_POST["category_alias"]."' , `category_order` = '".$_POST["category_order"]."' WHERE `cmd_category_id` = '".$_POST["cmd_category_id"]."'");
+		$DBRESULT = $pearDB->query("UPDATE `command_categories` SET `category_name` = '".$pearDB->escape($_POST["category_name"])."' , `category_alias` = '".$pearDB->escape($_POST["category_alias"])."' , `category_order` = '".$pearDB->escape($_POST["category_order"])."' WHERE `cmd_category_id` = '".$pearDB->escape($_POST["cmd_category_id"])."'");
 	}
 	
 	function deleteCommandCategorieInDB($sc_id = NULL){
```
