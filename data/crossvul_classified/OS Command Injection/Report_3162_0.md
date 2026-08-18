# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3162_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3162_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 20-60 of the vulnerable file.

#########################################
*/

global $path_nagios_bin;
global $path_nagios_etc;

$array_msg = array (
	0 => "EON - Standard Error ",
	1 => "EON - Could not connect to Database ",
	2 => "EON - Could not find file ",
	3 => "EON - Could not write in file (verify access) ",
	4 => "EON - Could not get the value in parameters : ",
	5 => "EON - Error uploading file ",
	6 => "EON - Operation successful",
	7 => "EON - Form error ",
	8 => "EON - User / Group ",
	9 => "EON - Graph ",
	10 => "EON - Name Error",
	11 => "EON - GED");

$array_tools = array (
	"snmpwalk"		 => "tools/snmpwalk.php",
	"show interface" => "tools/interface.php",
	"show port" 	 => "tools/port.php");

$array_group_mgt = array (
    "label.admin_group.select_add" => "add_group",
	"label.admin_group.select_del" => "delete_group",
	"label.admin_group.select_import" => "import_user",
	);

$array_user_mgt = array (
	"label.admin_user.select_add" => "add_user",
	"label.admin_user.select_del" => "delete_user");

$array_bp_mgt = array (
	"add" 				=> "add_process",
	"delete" 			=> "delete_process",
	"delete on cascade" => "cascade_delete",
	"delete all" 		=> "delete_all",
	"duplicate" 		=> "duplicate",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,8 @@
 	10 => "EON - Name Error",
 	11 => "EON - GED");
 
+$array_modules = array ("glpi","ocsinventory-reports");
+	
 $array_tools = array (
 	"snmpwalk"		 => "tools/snmpwalk.php",
 	"show interface" => "tools/interface.php",
@@ -60,6 +62,8 @@
 	"duplicate" 		=> "duplicate",
 	"back-up file" 		=> "backup");
 
+$array_ged_queues = array("active","sync","history");
+		
 $array_ged_types = array(
 	0 => "label.all",
 	1 => "services",
```
