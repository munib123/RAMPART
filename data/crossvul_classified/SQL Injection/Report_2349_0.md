# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2349_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2349_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 11-51 of the vulnerable file.

// breadcrumbs and page title
$navwhere['text1'] = $main_smarty->get_config_vars('PLIGG_Visual_Breadcrumb_Recover_Password');
$navwhere['link1'] = getmyurl('loginNoVar', '');
$main_smarty->assign('navbar_where', $navwhere);
$main_smarty->assign('posttitle', $main_smarty->get_config_vars('PLIGG_Visual_Breadcrumb_Recover_Password'));

// sidebar
$main_smarty = do_sidebar($main_smarty);

// initialize error message variable
$errorMsg="";

// if user requests to logout
if($my_pligg_base){
	if (strpos($_GET['return'],$my_pligg_base)!==0) $_GET['return']=$my_pligg_base . '/';
	if (strpos($_POST['return'],$my_pligg_base)!==0) $_POST['return']=$my_pligg_base . '/';
}

$id=sanitize($_REQUEST['id'], 3);
$n=sanitize($_REQUEST['n'], 3);
$username=base64_decode($id);
$sql="SELECT * FROM `" . table_users . "` where `user_login` = '".$username."' AND `last_reset_request` = FROM_UNIXTIME('".$n."') AND user_level!='Spammer'";
		
$user = $db->get_row($sql);

if($user){
	if( (isset($_POST["processrecover"]) && is_numeric($_POST["processrecover"]))){
	
		if($_POST["processrecover"]==1){
			
			$error=false;
			
			$password = sanitize($_POST["reg_password"], 3);
			$password2 = sanitize($_POST["reg_password2"], 3);
			if(strlen($password) < 5 ) { // if password is less than 5 characters
				$form_password_error[] = $main_smarty->get_config_vars('PLIGG_Visual_Register_Error_FiveCharPass');
				$error = true;
			}
			if($password !== $password2) { // if both passwords do not match
				$form_password_error[] = $main_smarty->get_config_vars('PLIGG_Visual_Register_Error_NoPassMatch');
				$error = true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,7 +28,9 @@
 
 $id=sanitize($_REQUEST['id'], 3);
 $n=sanitize($_REQUEST['n'], 3);
-$username=base64_decode($id);
+$idTemp=base64_decode($id);
+$username=sanitize($idTemp ,3);
+
 $sql="SELECT * FROM `" . table_users . "` where `user_login` = '".$username."' AND `last_reset_request` = FROM_UNIXTIME('".$n."') AND user_level!='Spammer'";
 		
 $user = $db->get_row($sql);
```
