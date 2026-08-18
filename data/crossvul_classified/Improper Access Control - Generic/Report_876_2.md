# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 876_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `876_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-20 of the vulnerable file.

<?php

//header('Content-Type: application/json; charset=UTF-8');

if(file_exists('/usr/bin/lsb_release')) {
	echo substr(shell_exec('/usr/bin/lsb_release -ds'),0,21); //ubuntu - debian
	}

elseif(file_exists('/etc/SuSE-release')) {
	echo substr(shell_exec('head -1 /etc/SuSE-release'),0,22);  //opensuse
  }
  
elseif(file_exists('/etc/redhat-release')) {
	echo substr(shell_exec('head -1 /etc/redhat-release'),0,21);  //redhat - centOS
  }

else {
	echo "Linux";
	}  
  
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 <?php
 
-//header('Content-Type: application/json; charset=UTF-8');
+Session::checkLoginUser();
+Session::checkRight("profile", READ);
 
 if(file_exists('/usr/bin/lsb_release')) {
 	echo substr(shell_exec('/usr/bin/lsb_release -ds'),0,21); //ubuntu - debian
```
