# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4274_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4274_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 353-393 of the vulnerable file.

			return $_POST[$field_name];	
	else 
		return $_GET[$field_name];
}

// Delete accents
function stripAccents($str, $charset='utf-8'){
    $str = htmlentities($str, ENT_NOQUOTES, $charset);

    $str = preg_replace('#\&([A-za-z])(?:acute|cedil|circ|grave|ring|tilde|uml)\;#', '\1', $str);
    $str = preg_replace('#\&([A-za-z]{2})(?:lig)\;#', '\1', $str); 
    $str = preg_replace('#\&[^;]+\;#', '', $str); 

    return $str;
}

// Add Logs
function logging($module,$command,$user=false){
	global $database_eonweb;
	global $dateformat;
	if($user)
		sqlrequest($database_eonweb,"insert into logs values ('','".time()."','$user','$module','$command','".$_SERVER["REMOTE_ADDR"]."');");
	elseif(isset($_COOKIE['user_name']))
		sqlrequest($database_eonweb,"insert into logs values ('','".time()."','".$_COOKIE['user_name']."','$module','$command','".$_SERVER["REMOTE_ADDR"]."');");
}

// Time
function getmtime(){
  
    $temps = microtime();
    $temps = explode(' ', $temps);
    return $temps[1] + $temps[0];
 
}

// Get the informations of nagios' config's file.
function getBpProcess(){
	
	global $path_nagiosbpcfg ;
	global $path_nagiosbpcfg_lock ;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -370,10 +370,13 @@
 function logging($module,$command,$user=false){
 	global $database_eonweb;
 	global $dateformat;
-	if($user)
+	if($user){
+		$user = htmlspecialchars($user);
 		sqlrequest($database_eonweb,"insert into logs values ('','".time()."','$user','$module','$command','".$_SERVER["REMOTE_ADDR"]."');");
-	elseif(isset($_COOKIE['user_name']))
-		sqlrequest($database_eonweb,"insert into logs values ('','".time()."','".$_COOKIE['user_name']."','$module','$command','".$_SERVER["REMOTE_ADDR"]."');");
+	}elseif(isset($_COOKIE['user_name'])){
+		$user = htmlspecialchars($_COOKIE['user_name']);
+		sqlrequest($database_eonweb,"insert into logs values ('','".time()."','".$user."','$module','$command','".$_SERVER["REMOTE_ADDR"]."');");
+	}
 }
 
 // Time
```
