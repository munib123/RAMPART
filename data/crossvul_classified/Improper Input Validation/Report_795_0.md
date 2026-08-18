# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 795_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `795_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 1-28 of the vulnerable file.

<?php

/*
 * ecran_securite.php
 * ------------------
 */

define('_ECRAN_SECURITE', '1.3.10'); // 2019-02-12

/*
 * Documentation : http://www.spip.net/fr_article4200.html
 */

/*
 * Test utilisateur
 */
if (isset($_GET['test_ecran_securite']))
	$ecran_securite_raison = 'test '._ECRAN_SECURITE;

/*
 * Monitoring
 * var_isbot=0 peut etre utilise par un bot de monitoring pour surveiller la disponibilite d'un site vu par les users
 * var_isbot=1 peut etre utilise pour monitorer la disponibilite pour les bots (sujets a 503 de delestage si
 * le load depasse ECRAN_SECURITE_LOAD)
 */
if (!defined('_IS_BOT') and isset($_GET['var_isbot'])){
	define('_IS_BOT', $_GET['var_isbot'] ? true : false);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
  * ------------------
  */
 
-define('_ECRAN_SECURITE', '1.3.10'); // 2019-02-12
+define('_ECRAN_SECURITE', '1.3.11'); // 2019-04-08
 
 /*
  * Documentation : http://www.spip.net/fr_article4200.html
@@ -491,7 +491,7 @@
 /*
  * Réinjection des clés en html dans l'admin r19561
  */
-if (strpos($_SERVER['REQUEST_URI'], "ecrire/") !== false){
+if (strpos($_SERVER['REQUEST_URI'], "ecrire/") !== false or isset($_REQUEST['var_memotri'])){
 	$zzzz = implode("", array_keys($_REQUEST));
 	if (strlen($zzzz) != strcspn($zzzz, '<>"\''))
 		$ecran_securite_raison = 'Cle incorrecte en $_REQUEST';
```
