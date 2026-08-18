# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 5583_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5583_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-43 of the vulnerable file.

<?php

require_once "_include/error.php";

_debug("Initializing ---------------------------------------------------");
if(isset($_SERVER)) {
	$GLOBALS['__GET']	=&$_GET;
	$GLOBALS['__POST']	=&$_POST;
	$GLOBALS['__SERVER']	=&$_SERVER;
	$GLOBALS['__FILES']	=&$_FILES;
} elseif(isset($HTTP_SERVER_VARS)) {
	$GLOBALS['__GET']	=&$HTTP_GET_VARS;
	$GLOBALS['__POST']	=&$HTTP_POST_VARS;
	$GLOBALS['__SERVER']	=&$HTTP_SERVER_VARS;
	$GLOBALS['__FILES']	=&$HTTP_POST_FILES;
} else {
	die("<B>ERROR: Your PHP version is too old</B><BR>".
	"You need at least PHP 4.0.0 to run QuiXplorer; preferably PHP 4.3.1 or higher.");
}
//------------------------------------------------------------------------------
// Get Action
if(isset($GLOBALS['__GET']["action"])) $GLOBALS["action"]=$GLOBALS['__GET']["action"];
else $GLOBALS["action"]="list";
if($GLOBALS["action"]=="post" && isset($GLOBALS['__POST']["do_action"])) {
	$GLOBALS["action"]=$GLOBALS['__POST']["do_action"];
}
if($GLOBALS["action"]=="") $GLOBALS["action"]="list";
$GLOBALS["action"]=stripslashes($GLOBALS["action"]);

// Get Item
if(isset($GLOBALS['__GET']["item"])) $GLOBALS["item"]=stripslashes($GLOBALS['__GET']["item"]);
else $GLOBALS["item"]="";
// Get Sort
if(isset($GLOBALS['__GET']["order"])) $GLOBALS["order"]=stripslashes($GLOBALS['__GET']["order"]);
else $GLOBALS["order"]="name";
if($GLOBALS["order"]=="") $GLOBALS["order"]=="name";
// Get Sortorder (yes==up)
if(isset($GLOBALS['__GET']["srt"])) $GLOBALS["srt"]=stripslashes($GLOBALS['__GET']["srt"]);
else $GLOBALS["srt"]="yes";
if($GLOBALS["srt"]=="") $GLOBALS["srt"]=="yes";

// Necessary files
ob_start(); // prevent unwanted output
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,15 +17,23 @@
 	die("<B>ERROR: Your PHP version is too old</B><BR>".
 	"You need at least PHP 4.0.0 to run QuiXplorer; preferably PHP 4.3.1 or higher.");
 }
-//------------------------------------------------------------------------------
-// Get Action
-if(isset($GLOBALS['__GET']["action"])) $GLOBALS["action"]=$GLOBALS['__GET']["action"];
-else $GLOBALS["action"]="list";
+
+_debug("xxx3 action: " . $GLOBALS['__GET']["action"] . "/" . $GLOBALS["__GET"]["do_action"] . "/" . (isset($GLOBALS['__GET']['action']) ? "true" : "false"));
+if (isset($GLOBALS['__GET']["action"]))
+{
+    $GLOBALS["action"]=$GLOBALS['__GET']["action"];
+}
+else
+{
+    $GLOBALS["action"]="list";
+}
 if($GLOBALS["action"]=="post" && isset($GLOBALS['__POST']["do_action"])) {
 	$GLOBALS["action"]=$GLOBALS['__POST']["do_action"];
 }
 if($GLOBALS["action"]=="") $GLOBALS["action"]="list";
 $GLOBALS["action"]=stripslashes($GLOBALS["action"]);
+_debug("xxx3 action: " . $GLOBALS['__GET']["action"] . "/" . $GLOBALS["__GET"]["do_action"] . "/" . (isset($GLOBALS['__GET']['action']) ? "true" : "false"));
+
 
 // Get Item
 if(isset($GLOBALS['__GET']["item"])) $GLOBALS["item"]=stripslashes($GLOBALS['__GET']["item"]);
```
