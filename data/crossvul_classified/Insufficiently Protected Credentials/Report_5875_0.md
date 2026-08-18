# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 5875_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5875_0`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 107-147 of the vulnerable file.

		return 0;
	} 
}

//compare password
//return value -> 0 equal ;1 Not equal
function password_check($oldpassword, $profile_id)
{
	global $db_user_id, $db_group_id, $db_user_name, $db_user_email, $db_user_password, $db_table_user_name; 
	global $db_table_group_name, $auth_user_class, $auth_alt_user_class, $table_prefix, $db_raid, $phpraid_config;
	global $pwd_hasher;

	$sql_passchk = sprintf("SELECT " . $db_user_password . " FROM " . $table_prefix . $db_table_user_name . 
						" WHERE " . $db_user_id . " = %s", quote_smart($profile_id)
			);
	$result_passchk = $db_raid->sql_query($sql_passchk) or print_error($sql_passchk, mysql_error(), 1);
	$data_passchk = $db_raid->sql_fetchrow($result_passchk, true);
	$db_pass = $data_passchk[$db_user_password];
	
	$initString = '$H$';
	$testVal = $pwd_hasher->CheckPassword($oldpassword, $db_pass);
	if ($testVal)
		return 0;
	else
		return 1;
}

function phpraid_login() 
{
	global $db_user_id, $db_group_id, $db_user_name, $db_user_email, $db_user_password, $db_table_user_name; 
	global $db_table_group_name, $auth_user_class, $auth_alt_user_class, $table_prefix, $db_raid, $phpraid_config;

	$wrmuserpassword = $username = $password = "";

	if(isset($_POST['username'])){
		$username = scrub_input(strtolower(utf8_decode($_POST['username'])));
		$password = $_POST['password'];
	} elseif(isset($_COOKIE['username']) && isset($_COOKIE['password'])) {
		$username = scrub_input(strtolower($_COOKIE['username']));
		$password = scrub_input($_COOKIE['password']);
	} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,11 +124,12 @@
 	$db_pass = $data_passchk[$db_user_password];
 	
 	$initString = '$H$';
-	$testVal = $pwd_hasher->CheckPassword($oldpassword, $db_pass);
+	$testVal = $pwd_hasher->CheckPassword($oldpassword, $db_pass, $initString);
+
 	if ($testVal)
-		return 0;
+		return TRUE;
 	else
-		return 1;
+		return FALSE;
 }
 
 function phpraid_login() 
@@ -162,7 +163,6 @@
 			);
 
 	$result = $db_raid->sql_query($sql) or print_error($sql, mysql_error(), 1);
-
 	//WRM database
 	//$sql = sprintf("SELECT username, password FROM " . $phpraid_config['db_prefix'] . "profile WHERE username = %s",
 	//				quote_smart($username)
```
