# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3300_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3300_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php 
use \Dropbox as dbx;

function verify(){
	echo $_GET['challenge'];
}

function webhook(){
	#'''Receive a list of changed user IDs from Dropbox and process each.'''

	//1 recup de l'header et verifie si signature dropbox
	$signature = (isset(getallheaders()['X-Dropbox-Signature'])) ? getallheaders()['X-Dropbox-Signature'] : "signature invalide" ;
	//comment vérifier la signature ? (non facultatif)

	//2 recup du json
	$data = file_get_contents("php://input"); 
	$uidList = json_decode($data);
	// file_put_contents('dblog.txt',$data."\n".$uidList);

	//3 repondre rapidement
	echo 'Lancement process_user';
	process_user();
	//nb  : on n'utilise pas les uid donc cette fonction pourrait se résumer en process_user();
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 use \Dropbox as dbx;
 
 function verify(){
-	echo $_GET['challenge'];
+	echo htmlspecialchars($_GET['challenge']);
 }
 
 function webhook(){
```
