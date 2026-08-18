# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3162_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3162_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

$action = isset($_GET['action']) ? $_GET['action'] : false;
$bp_name = isset($_GET['bp_name']) ? $_GET['bp_name'] : false;
$host_name = isset($_GET['host_name']) ? $_GET['host_name'] : false;
$service = isset($_GET['service']) ? $_GET['service'] : false;
$new_services = isset($_GET['new_services']) ? $_GET['new_services'] : false;

$uniq_name = isset($_GET['uniq_name']) ? $_GET['uniq_name'] : false;
$uniq_name_orig = isset($_GET['uniq_name_orig']) ? $_GET['uniq_name_orig'] : false;
$process_name = isset($_GET['process_name']) ? $_GET['process_name'] : false;
$display = isset($_GET['display']) ? $_GET['display'] : false;
$url = isset($_GET['url']) ? $_GET['url'] : false;
$command = isset($_GET['command']) ? $_GET['command'] : false;
$type = isset($_GET['type']) ? $_GET['type'] : false;
$min_value = isset($_GET['min_value']) ? $_GET['min_value'] : false;

try {
	$bdd = new PDO('mysql:host=localhost;dbname=nagiosbp', 'root', 'root66');
} catch(Exception $e) {
	echo "Connection failed: " . $e->getMessage();
	exit('Impossible de se connecter à la base de données.');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,6 @@
 <?php
+
+include("../../../include/config.php");
 
 $action = isset($_GET['action']) ? $_GET['action'] : false;
 $bp_name = isset($_GET['bp_name']) ? $_GET['bp_name'] : false;
@@ -16,7 +18,7 @@
 $min_value = isset($_GET['min_value']) ? $_GET['min_value'] : false;
 
 try {
-	$bdd = new PDO('mysql:host=localhost;dbname=nagiosbp', 'root', 'root66');
+	$bdd = new PDO('mysql:host=localhost;dbname='.$database_nagios, $database_username, $database_password);
 } catch(Exception $e) {
 	echo "Connection failed: " . $e->getMessage();
 	exit('Impossible de se connecter à la base de données.');
@@ -73,17 +75,21 @@
 }
 
 function delete_bp($bp,$bdd){
-    $sql = "delete from bp where name = '" . $bp . "'";
-    $bdd->exec($sql);
-
-	$sql = "delete from bp_services where bp_name = '" . $bp . "'";
-    $bdd->exec($sql);
-
-	$sql = "delete from bp_links where bp_name = '" . $bp . "'";
-	$bdd->exec($sql);
-	
-	$sql = "delete from bp_links where bp_link = '" . $bp . "'";
-	$bdd->exec($sql);
+	$sql = "delete from bp where name = ?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp));
+
+	$sql = "delete from bp_services where bp_name = ?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp));
+
+	$sql = "delete from bp_links where bp_name = ?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp));
+	
+	$sql = "delete from bp_links where bp_link = ?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp));
 }
 
 function list_services($host_name){
@@ -112,8 +118,9 @@
 }
 
 function list_process($bp,$display,$bdd){
-	$sql = "select name from bp where is_define = 1 and name!='".$bp."' and priority = '" . $display . "'";
-	$req = $bdd->query($sql);
+	$sql = "select name from bp where is_define = 1 and name!=? and priority = ?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp,$display));
 	$process = $req->fetchall();
 
     echo json_encode($process);
@@ -130,20 +137,20 @@
 			$list_services[] = $service;
 		}
 	}
-	$sql = "select service,host from bp_services where bp_name = '" . $bp . "'";
-	$req = $bdd->query($sql);
-
-	$sql = "delete from bp_services where bp_name = '" . $bp . "'";
-	$bdd->exec($sql);
+
+	$sql = "delete from bp_services where bp_name = ?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp));
 
 	if(count($services) > 0){
-		$sql = "update bp set is_define = 1 where name = '" . $bp . "'";
-		$bdd->exec($sql);
-	}
-
+		$sql = "update bp set is_define = 1 where name = ?";
+		$req = $bdd->prepare($sql);
+		$req->execute(array($bp));
+	}
 	else{
-		$sql = "update bp set is_define = 0 where name = '" . $bp . "'";
-        $bdd->exec($sql);
+		$sql = "update bp set is_define = 0 where name = ?";
+		$req = $bdd->prepare($sql);
+		$req->execute(array($bp));
     }
 
 	if(is_array($services)) {
@@ -152,37 +159,43 @@
 			$host = $value[0];
 			$service = $value[1];
 			echo $service;
-			$sql = "insert into bp_services (bp_name,host,service) values('" . trim($bp) . "','" . $host . "','" . $service . "')";
-			$bdd->exec($sql);
+			$sql = "insert into bp_services (bp_name,host,service) values(?,?,?)";
+			$req = $bdd->prepare($sql);
+			$req->execute(array(trim($bp),$host,$service));
 		}
 	}
 }
 
 function add_process($bp,$process,$bdd){
-    $sql = "delete from bp_links where bp_name = '" . $bp . "'";
-    $bdd->exec($sql);
-	$sql = "update bp set is_define = 0 where name = '" . $bp . "'";
-	$bdd->exec($sql);	
+	$sql = "delete from bp_links where bp_name = ?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp));
+	$sql = "update bp set is_define = 0 where name = ?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp));
 
     if(count($process) > 0 and is_array($process)){
-        $sql = "update bp set is_define = 1 where name = '" . $bp . "'";
-        $bdd->exec($sql);
+		$sql = "update bp set is_define = 1 where name = ?";
+		$req = $bdd->prepare($sql);
+		$req->execute(array($bp));
 	
 		foreach($process as $values){
 			$value = explode("::", $values);
 			$bp_link = $value[1];
 
-			$sql = "insert into bp_links (bp_name,bp_link) values('" . $bp . "','" . $bp_link . "')";
-
-			$bdd->exec($sql);
+			$sql = "insert into bp_links (bp_name,bp_link) values(?,?)";
+
+			$req = $bdd->prepare($sql);
+			$req->execute(array($bp,$bp_link));
 		}	
 	}
 }
 
 function check_app_exists($uniq_name, $bdd)
 {
-	$sql = "select count(*) from bp where name = '" . $uniq_name . "';";
-	$req = $bdd->query($sql);
+	$sql = "select count(*) from bp where name = ?;";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($uniq_name));
 	$bp_exist = $req->fetch(PDO::FETCH_NUM);
 	
 	if($bp_exist[0] == 1){
@@ -196,34 +209,41 @@
 	if($type != 'MIN'){
 		$min_value = "";
 	}
-	$sql = "select count(*) from bp where name = '" . $uniq_name . "';";
-	$req = $bdd->query($sql);
+	$sql = "select count(*) from bp where name = ?;";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($uniq_name));
 	$bp_exist = $req->fetch();
 
 	// add
 	if($bp_exist[0] == 0 and empty($uniq_name_orig)){
-		$sql = "insert into bp (name,description,priority,type,command,url,min_value) values('" . $uniq_name ."','" . $process_name ."','" . $display . "','" . $type . "','" . $command . "','" . $url . "','" . $min_value . "')";
-		$bdd->exec($sql);
+		$sql = "insert into bp (name,description,priority,type,command,url,min_value) values(?,?,?,?,?,?,?)";
+		$req = $bdd->prepare($sql);
+		$req->execute(array($uniq_name,$process_name,$display,$type,$command,$url,$min_value));
 	}
 	// uniq name modification
 	elseif($uniq_name_orig != $uniq_name) {
 		if($bp_exist[0] != 0){
 			// TODO QUENTIN
 		} else {
-			$sql = "update bp set name = '" . $uniq_name . "',description = '" . $process_name . "',priority = '" . $display . "',type = '" . $type . "',command = '" . $command . "',url = '" . $url . "',min_value = '" . $min_value . "' where name = '" . $uniq_name_orig . "'";
-			$bdd->exec($sql);
-			$sql = "update bp_links set bp_name = '" . $uniq_name . "' where bp_name = '" . $uniq_name_orig . "'";
-			$bdd->exec($sql);		
-			$sql = "update bp_links set bp_link = '" . $uniq_name . "' where bp_link = '" . $uniq_name_orig . "'";
-			$bdd->exec($sql);
-			$sql = "update bp_services set bp_name = '" . $uniq_name . "' where bp_name = '" . $uniq_name_orig . "'";					
-			$bdd->exec($sql);		
+			$sql = "update bp set name = ?,description = ?,priority = ?,type = ?,command = ?,url = ?,min_value = ? where name = ?";
+			$req = $bdd->prepare($sql);
+			$req->execute(array($uniq_name,$process_name,$display,$type,$command,$url,$min_value,$uniq_name_orig));
+			$sql = "update bp_links set bp_name = ? where bp_name = ?";
+			$req = $bdd->prepare($sql);
+			$req->execute(array($uniq_name,$uniq_name_orig));	
+			$sql = "update bp_links set bp_link = ? where bp_link = ?";
+			$req = $bdd->prepare($sql);
+			$req->execute(array($uniq_name,$uniq_name_orig));
+			$sql = "update bp_services set bp_name = ? where bp_name = ?";					
+			$req = $bdd->prepare($sql);
+			$req->execute(array($uniq_name,$uniq_name_orig));	
 		}
 	}	
 	// modification
 	else{
-		$sql = "update bp set name = '" . $uniq_name . "',description = '" . $process_name . "',priority = '" . $display . "',type = '" . $type . "',command = '" . $command . "',url = '" . $url . "',min_value = '" . $min_value . "' where name = '" . $uniq_name . "'";
-		$bdd->exec($sql);	
+		$sql = "update bp set name = ?,description = ?,priority = ?,type = ?,command = ?,url = ?,min_value = ? where name = ?";
+		$req = $bdd->prepare($sql);
+		$req->execute(array($uniq_name,$process_name,$display,$type,$command,$url,$min_value,$uniq_name));
 	}
 }
 
@@ -252,16 +272,18 @@
 
 function build_file_recursive($bdd,$bp_file,$bp_informations,$bp_sons){
 
-	$sql = "SELECT bp_link FROM bp_links where bp_name='".$bp_informations['name']."'";
-	$req = $bdd->query($sql);
+	$sql = "SELECT bp_link FROM bp_links where bp_name=?";
+	$req = $bdd->prepare($sql);
+	$req->execute(array($bp_informations['name']));
... (diff truncated)
```
