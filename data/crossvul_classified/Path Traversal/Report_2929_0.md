# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 2929_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2929_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php
session_start();
if (empty($_POST) && !empty($_SESSION) && !isset($_REQUEST['stage'])) {
    $_POST = $_SESSION;
} else {
    $_SESSION = array_replace($_SESSION, $_POST);
}

$stage = isset($_POST['stage']) ? $_POST['stage'] : 0;

// Before we do anything, if we see config.php, redirect back to the homepage.
if (file_exists('../config.php') && $stage != 6) {
    header("Location: /");
    exit;
}

// do not use the DB in init, we'll bring it up ourselves
$init_modules = array('web', 'nodb');
if ($stage > 3) {
    $init_modules[] = 'auth';
}
require realpath(__DIR__ . '/..') . '/includes/init.php';

// List of php modules we expect to see
$modules = array('gd','mysqli','mcrypt');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 session_start();
 if (empty($_POST) && !empty($_SESSION) && !isset($_REQUEST['stage'])) {
     $_POST = $_SESSION;
-} else {
+} elseif (!file_exists("../config.php")) {
     $_SESSION = array_replace($_SESSION, $_POST);
 }
 
@@ -52,7 +52,9 @@
 // Check we can connect to MySQL DB, if not, back to stage 1 :)
 if ($stage > 1) {
     try {
-        dbConnect();
+        if ($stage != 6) {
+            dbConnect();
+        }
         if ($stage == 2 && $_SESSION['build-ok'] == true) {
             $stage = 3;
             $msg = "It appears that the database is already setup so have moved onto stage $stage";
```
