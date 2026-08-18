# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3162_4
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3162_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 8-37 of the vulnerable file.

# APPLICATION : eonweb for eyesofnetwork project
#
# LICENCE :
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
#########################################
*/

include("../../include/config.php");
include("../../include/function.php");

// Search function for Jquery an exit
if(isset($_GET['term']) && isset($_GET['request']) && $_GET['request'] == "search_user") {
	$result=sqlrequest($database_eonweb,"select * from ldap_users_extended where (user LIKE '%".$_GET['term']."%') OR (login LIKE '%".$_GET['term']."%') order by user");
	
	$array = array();
	while ($line = mysqli_fetch_array($result)){
		array_push($array, $line[0]);
	}
	echo json_encode($array);
}

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,8 @@
 
 // Search function for Jquery an exit
 if(isset($_GET['term']) && isset($_GET['request']) && $_GET['request'] == "search_user") {
-	$result=sqlrequest($database_eonweb,"select * from ldap_users_extended where (user LIKE '%".$_GET['term']."%') OR (login LIKE '%".$_GET['term']."%') order by user");
+	$sql="select * from ldap_users_extended where (user LIKE ?) OR (login LIKE ?) order by user";
+	$result=sqlrequest($database_eonweb,$sql,false,array("ss","%".$_GET['term']."%","%".$_GET['term']."%"));
 	
 	$array = array();
 	while ($line = mysqli_fetch_array($result)){
```
