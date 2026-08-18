# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 632_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `632_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 46-88 of the vulnerable file.

$tl_and_version = "TestLink {$_SESSION['testlink_version']} ";

define('LEN_PWD_TL_1_0_4',15);
define('ADD_DIR',1);

$migration_process = '';
$sql_update_schema = array();
$sql_update_data   = array();

// get db info from session
$san = '/[^A-Za-z0-9\-]/';
$db_name = trim($_SESSION['databasename']);
$db_name = preg_replace($san,'',$db_name);

$db_table_prefix = trim($_SESSION['tableprefix']);
$db_table_prefix = preg_replace($san,'',$db_table_prefix);

$db_server = trim($_SESSION['databasehost']);
$db_server = preg_replace($san,'',$db_server);

$db_admin_name = trim($_SESSION['databaseloginname']);
$db_admin_name = preg_replace($san,'',$db_admin_name);

$db_admin_pass = trim($_SESSION['databaseloginpassword']);
$db_admin_pass = preg_replace($san,'',$db_admin_pass);

$db_type = trim($_SESSION['databasetype']);
$db_type = preg_replace($san,'',$db_type);

$tl_db_login = trim($_SESSION['tl_loginname']);
$tl_db_login = preg_replace($san,'',$tl_db_login);

$tl_db_passwd = trim($_SESSION['tl_loginpassword']);
$tl_db_passwd = preg_replace($san,'',$tl_db_passwd);



$sql_create_schema = array();
$sql_create_schema[] = "sql/{$db_type}/testlink_create_tables.sql";
$a_sql_schema = array();
$a_sql_schema[] = $sql_create_schema;

$sql_default_data = array();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,20 +63,23 @@
 $db_server = trim($_SESSION['databasehost']);
 $db_server = preg_replace($san,'',$db_server);
 
-$db_admin_name = trim($_SESSION['databaseloginname']);
-$db_admin_name = preg_replace($san,'',$db_admin_name);
-
 $db_admin_pass = trim($_SESSION['databaseloginpassword']);
 $db_admin_pass = preg_replace($san,'',$db_admin_pass);
 
 $db_type = trim($_SESSION['databasetype']);
 $db_type = preg_replace($san,'',$db_type);
 
-$tl_db_login = trim($_SESSION['tl_loginname']);
-$tl_db_login = preg_replace($san,'',$tl_db_login);
-
 $tl_db_passwd = trim($_SESSION['tl_loginpassword']);
 $tl_db_passwd = preg_replace($san,'',$tl_db_passwd);
+
+
+// will limit length to avoi some kind of injection
+// Choice: 32 
+$tl_db_login = trim($_SESSION['tl_loginname']);
+$tl_db_login = substr(preg_replace($san,'',$tl_db_login),0,32);
+
+$db_admin_name = trim($_SESSION['databaseloginname']);
+$db_admin_name = substr(preg_replace($san,'',$db_admin_name),0,32);
 
 
 
```
