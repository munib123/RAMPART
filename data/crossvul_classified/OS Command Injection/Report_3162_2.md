# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3162_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3162_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 1-20 of the vulnerable file.

<?php
  // Mot tapé par l'utilisateur
  $q = $_GET['query'];
	$table_name = $_GET['table_name'];

    try {
        $bdd = new PDO('mysql:host=localhost;dbname=lilac', 'root', 'root66');
    } catch(Exception $e) {
		 echo "Connection failed: " . $e->getMessage();
        exit('Impossible de se connecter à la base de données.');
    }

    // Requête SQL
    $requete = "SELECT name FROM " . $table_name .  " WHERE name LIKE '". $q ."%' LIMIT 0, 10";

	foreach  ($bdd->query($requete) as $row) {
		$suggestions['suggestions'][] = $row['name'];
	}
    echo json_encode($suggestions);
?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,20 +1,24 @@
 <?php
-  // Mot tapé par l'utilisateur
-  $q = $_GET['query'];
-	$table_name = $_GET['table_name'];
 
-    try {
-        $bdd = new PDO('mysql:host=localhost;dbname=lilac', 'root', 'root66');
-    } catch(Exception $e) {
-		 echo "Connection failed: " . $e->getMessage();
-        exit('Impossible de se connecter à la base de données.');
-    }
+include("../../../include/config.php");
 
-    // Requête SQL
-    $requete = "SELECT name FROM " . $table_name .  " WHERE name LIKE '". $q ."%' LIMIT 0, 10";
+// Mot tapé par l'utilisateur
+$q = $_GET['query'];
+$table_name = $_GET['table_name'];
 
-	foreach  ($bdd->query($requete) as $row) {
-		$suggestions['suggestions'][] = $row['name'];
-	}
-    echo json_encode($suggestions);
+try {
+	$bdd = new PDO('mysql:host=localhost;dbname='.$database_lilac, $database_username, $database_password);
+} catch(Exception $e) {
+	 echo "Connection failed: " . $e->getMessage();
+	exit('Impossible de se connecter à la base de données.');
+}
+
+// Requête SQL
+$requete = "SELECT name FROM " . $table_name .  " WHERE name LIKE '". $q ."%' LIMIT 0, 10";
+
+foreach  ($bdd->query($requete) as $row) {
+	$suggestions['suggestions'][] = $row['name'];
+}
+echo json_encode($suggestions);
+
 ?>
```
