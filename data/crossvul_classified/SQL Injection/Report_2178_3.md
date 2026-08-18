# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2178_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2178_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

function teampass_api_enabled() {
	$bdd = teampass_connect();
	$response = $bdd->query("select valeur from ".$GLOBALS['pre']."misc WHERE type = 'admin' AND intitule = 'api'");
	return $response->fetch(PDO::FETCH_ASSOC);
}

function teampass_whitelist() {
    $bdd = teampass_connect();
	$apiip_pool = teampass_get_ips();
	if (count($apiip_pool) > 0 && !array_search($_SERVER['REMOTE_ADDR'], $apiip_pool)) {
		rest_error('IPWHITELIST');
	}
}

function teampass_connect() {
	require_once($GLOBALS['teampass_config_file']);
	try
	{
		$bdd = new PDO("mysql:host=".$GLOBALS['server'].";dbname=".$GLOBALS['database'], $GLOBALS['user'], $GLOBALS['pass']);
		return ($bdd);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,19 @@
 <?php
+/**
+ *
+ * @file          configapi.php
+ * @author        Nils Laumaillé
+ * @version       2.1.20
+ * @copyright     (c) 2009-2014 Nils Laumaillé
+ * @licensing     GNU AFFERO GPL 3.0
+ * @link		  http://www.teampass.net
+ *
+ * This library is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
+ */
+
+$teampass_config_file = "../includes/settings.php";
 
 function teampass_api_enabled() {
 	$bdd = teampass_connect();
@@ -9,7 +24,7 @@
 function teampass_whitelist() {
     $bdd = teampass_connect();
 	$apiip_pool = teampass_get_ips();
-	if (count($apiip_pool) > 0 && !array_search($_SERVER['REMOTE_ADDR'], $apiip_pool)) {
+	if (count($apiip_pool) > 0 && array_search($_SERVER['REMOTE_ADDR'], $apiip_pool) === false) {
 		rest_error('IPWHITELIST');
 	}
 }
@@ -169,36 +184,19 @@
 
 		if ($GLOBALS['request'][0] == "read") {
 			if($GLOBALS['request'][1] == "category") {
-				$array_category = explode(';',$GLOBALS['request'][2]);
-
-				foreach($array_category as $category) {
-					if(!preg_match_all("/^([\w\:\'\-\sàáâãäåçèéêëìíîïðòóôõöùúûüýÿ]+)$/i", $category,$result)) {
-						rest_error('CATEGORY_MALFORMED');
-					}
-				}
-
-				if(count($array_category) > 1 && count($array_category) < 5) {
-					for ($i = count($array_category); $i > 0; $i--) {
-						$slot = $i - 1;
-						if (!$slot) {
-							$category_query .= "select id from ".$GLOBALS['pre']."nested_tree where title LIKE '".$array_category[$slot]."' AND parent_id = 0";
-						} else {
-							$category_query .= "select id from ".$GLOBALS['pre']."nested_tree where title LIKE '".$array_category[$slot]."' AND parent_id = (";
-						}
-					}
-					for ($i = 1; $i < count($array_category); $i++) { $category_query .= ")"; }
-				} elseif (count($array_category) == 1) {
-					$category_query = "select id from ".$GLOBALS['pre']."nested_tree where title LIKE '".$array_category[0]."' AND parent_id = 0";
-				} else {
-					rest_error ('NO_CATEGORY');
-				}
-				$response = $bdd->query("select id,label,login,pw from ".$GLOBALS['pre']."items where id_tree = (".$category_query.")");
+				// get ids
+				if (strpos($GLOBALS['request'][2],",") > 0) {
+					$condition = "id_tree IN (".$GLOBALS['request'][2].")";
+				} else {
+					$condition = "id_tree = '".$GLOBALS['request'][2]."'";
+				}
+				$response = $bdd->query("select id,label,login,pw from ".$GLOBALS['pre']."items where ".$condition);
 				while ($data = $response->fetch())
 				{
 					$id = $data['id'];
 					$json[$id]['label'] = utf8_encode($data['label']);
 					$json[$id]['login'] = utf8_encode($data['login']);
-//					$json[$id]['pw'] = teampass_decrypt_pw($data['pw'],SALT,$rand_key);
+					$json[$id]['pw'] = teampass_decrypt_pw($data['pw'],SALT,$rand_key);
 				}
 			} elseif($GLOBALS['request'][1] == "item") {
 				$array_category = explode(';',$GLOBALS['request'][2]);
@@ -326,5 +324,3 @@
     if ($mac !== hash_hmac('sha256', $encrypted, $salt)) return null;
     return substr(rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $encrypted, 'ctr', $iv), "\0\4"), strlen($rand_key));
 }
-
-?>
```
