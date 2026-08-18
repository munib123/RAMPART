# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 1483_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1483_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 127-167 of the vulnerable file.


require_once($sourceFolder."/icons.lib.php");

///Defined here to set its access as global to the project
$dbase; 

///To connect to server
connect(); 

///Authentication process begins here
require_once($sourceFolder."/authenticate.lib.php");
$cookieSupported = checkCookieSupport();
if($cookieSupported==true)	session_start();
$userId=firstTimeGetUserId();
///Case 1 : request a page
if(isset($_GET['page']))
	$pageFullPath = strtolower($_GET['page']);
///Case 2 : request for a user profile page
else if(isset($_GET['user'])) {
	$publicPageRequest = true;
	$userProfileId = $_GET['user'];
	//This is just to prevent parsing a NULL url when someone misplaces the code for User profile parser
	$pageFullPath = "home";
}
else $pageFullPath = "home";

///Retrieve the action, default is "view"
if(isset($_GET['action']))
	$action = strtolower(escape($_GET['action']));
else	$action = "view";

///Just to check if server is alive, an alternative of Ping
if ($action == 'keepalive') 
	die("OK: " . rand());

///Get all the global settings from the database and convert into variables
$globals=getGlobalSettings();
foreach($globals as $var=>$val) 
	$$var=$val;


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,7 +144,7 @@
 ///Case 2 : request for a user profile page
 else if(isset($_GET['user'])) {
 	$publicPageRequest = true;
-	$userProfileId = $_GET['user'];
+	$userProfileId = safe_html(escape($_GET['user']));
 	//This is just to prevent parsing a NULL url when someone misplaces the code for User profile parser
 	$pageFullPath = "home";
 }
```
