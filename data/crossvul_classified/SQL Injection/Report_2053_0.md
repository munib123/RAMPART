# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2053_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2053_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 10-50 of the vulnerable file.

	include 'mod/statistik/counter.php';

	class usersOnline {

		var $timeout = 600;
		var $count = 0;
		var $error;
		var $i = 0;
		
		function usersOnline () {
			$this->timestamp = time();
			$this->ip = $this->ipCheck();
			$this->new_user();
			$this->delete_user();
			$this->count_users();
		}
		
		function ipCheck() {

			if (getenv('HTTP_CLIENT_IP')) {
				$ip = getenv('HTTP_CLIENT_IP');
			}
			elseif (getenv('HTTP_X_FORWARDED_FOR')) {
				$ip = getenv('HTTP_X_FORWARDED_FOR');
			}
			elseif (getenv('HTTP_X_FORWARDED')) {
				$ip = getenv('HTTP_X_FORWARDED');
			}
			elseif (getenv('HTTP_FORWARDED_FOR')) {
				$ip = getenv('HTTP_FORWARDED_FOR');
			}
			elseif (getenv('HTTP_FORWARDED')) {
				$ip = getenv('HTTP_FORWARDED');
			}
			else {
				$ip = $_SERVER['REMOTE_ADDR'];
			}
			return $ip;
		}
		
		function new_user() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,29 +27,29 @@
 		function ipCheck() {
 
 			if (getenv('HTTP_CLIENT_IP')) {
-				$ip = getenv('HTTP_CLIENT_IP');
+				$ip = mysql_real_escape_string(getenv('HTTP_CLIENT_IP'));
 			}
 			elseif (getenv('HTTP_X_FORWARDED_FOR')) {
-				$ip = getenv('HTTP_X_FORWARDED_FOR');
+				$ip = mysql_real_escape_string(getenv('HTTP_X_FORWARDED_FOR'));
 			}
 			elseif (getenv('HTTP_X_FORWARDED')) {
-				$ip = getenv('HTTP_X_FORWARDED');
+				$ip = mysql_real_escape_string(getenv('HTTP_X_FORWARDED'));
 			}
 			elseif (getenv('HTTP_FORWARDED_FOR')) {
-				$ip = getenv('HTTP_FORWARDED_FOR');
+				$ip = mysql_real_escape_string(getenv('HTTP_FORWARDED_FOR'));
 			}
 			elseif (getenv('HTTP_FORWARDED')) {
-				$ip = getenv('HTTP_FORWARDED');
+				$ip = mysql_real_escape_string(getenv('HTTP_FORWARDED'));
 			}
 			else {
-				$ip = $_SERVER['REMOTE_ADDR'];
+				$ip = mysql_real_escape_string($_SERVER['REMOTE_ADDR']);
 			}
 			return $ip;
 		}
 		
 		function new_user() {
 			global $db;
-			$insert = $db->sql_query("INSERT INTO `mod_useronline` (`timestamp`, `ip`) VALUES ('mysql_real_escape_string($this->timestamp)', 'mysql_real_escape_string($this->ip)')");
+			$insert = $db->sql_query("INSERT INTO `mod_useronline` (`timestamp`, `ip`) VALUES ('$this->timestamp', '$this->ip')");
 			if (!$insert) {
 				$this->error[$this->i] = "Unable to record new visitor\r\n";			
 				$this->i ++;
@@ -120,7 +120,7 @@
 
 	$yesterdaystart	 =	$daystart - (24*60*60);
 	$now			 =	time();
-	$ip				 =	getIP();
+	$ip				 =	mysql_real_escape_string(getIP());
 	
 
 	$r	= mysql_query("SELECT MAX( id ) AS total FROM `mod_visitcounter`");
@@ -140,12 +140,12 @@
 		//$query		 =  mysql_query ("DELETE FROM `mod_visitcounter` WHERE `id`<'$temp'");
 	}
 	
-	$item	=	mysql_fetch_assoc(mysql_query ("SELECT COUNT(*) AS `total` FROM `mod_visitcounter` WHERE `ip`='mysql_real_escape_string($ip)' AND (tm+'$locktime')>'$now'"));
+	$item	=	mysql_fetch_assoc(mysql_query ("SELECT COUNT(*) AS `total` FROM `mod_visitcounter` WHERE `ip`='$ip' AND (tm+'$locktime')>'$now'"));
 	$items	=	$item['total'];
 	
 	if (empty($items))
 	{
-		mysql_query ("INSERT INTO `mod_visitcounter` (`id`, `tm`, `ip`) VALUES ('', '$now', 'mysql_real_escape_string($ip)')");
+		mysql_query ("INSERT INTO `mod_visitcounter` (`id`, `tm`, `ip`) VALUES ('', '$now', '$ip')");
 	}
 	
 	$n				 = 	$all_visitors;
```
