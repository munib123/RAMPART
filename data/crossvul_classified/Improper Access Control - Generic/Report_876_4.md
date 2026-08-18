# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 876_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `876_4`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-32 of the vulnerable file.

<?php
define('GLPI_ROOT', '../../..');
include (GLPI_ROOT . "/inc/includes.php");
include (GLPI_ROOT . "/inc/config.php");

global $DB;

Session::checkLoginUser();
Session::checkRight("profile", READ);

//$ver = explode(" ",implode(" ",plugin_version_dashboard()));


// count years	
$query_y = "SELECT DISTINCT DATE_FORMAT( date, '%Y' ) AS year
FROM glpi_tickets
WHERE glpi_tickets.is_deleted = '0'
AND date IS NOT NULL
ORDER BY year DESC ";
	
$result_y = $DB->query($query_y);
$num_years = $DB->numrows($result_y);


// count months	
$query_m = "SELECT DISTINCT DATE_FORMAT( date, '%Y-%m' ) AS month
FROM glpi_tickets
WHERE glpi_tickets.is_deleted = '0'
AND date IS NOT NULL
ORDER BY month DESC ";
	
$result_m = $DB->query($query_m);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,9 +7,6 @@
 
 Session::checkLoginUser();
 Session::checkRight("profile", READ);
-
-//$ver = explode(" ",implode(" ",plugin_version_dashboard()));
-
 
 // count years	
 $query_y = "SELECT DISTINCT DATE_FORMAT( date, '%Y' ) AS year
```
