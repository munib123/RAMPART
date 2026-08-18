# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2178_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2178_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php

require_once('config.php');
require_once('functions.php');

header('Content-Type: application/json');

$teampass_api_enabled = teampass_api_enabled();
if (!in_array("1", $teampass_api_enabled)) {
	echo '{"err":"API access not allowed."}';
	exit;
}

teampass_whitelist();

parse_str($_SERVER['QUERY_STRING']);
$method = $_SERVER['REQUEST_METHOD'];
$request = explode("/", substr(@$_SERVER['PATH_INFO'], 1));

switch ($method) {
  case 'GET':
    rest_get();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,19 @@
 <?php
+/**
+ *
+ * @file          indexapi.php
+ * @author        Nils Laumaill�
+ * @version       2.1.20
+ * @copyright     (c) 2009-2014 Nils Laumaill�
+ * @licensing     GNU AFFERO GPL 3.0
+ * @link		  http://www.teampass.net
+ *
+ * This library is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
+ */
 
-require_once('config.php');
+//require_once('config.php');
 require_once('functions.php');
 
 header('Content-Type: application/json');
```
