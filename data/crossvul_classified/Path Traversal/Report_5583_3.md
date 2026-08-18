# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 5583_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5583_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 12-52 of the vulnerable file.

{
	static $perms = array (
			"read"		=> 0x0001,
			"create"	=> 0x0002,
			"change"	=> 0x0004,
			"delete"	=> 0x0008,
			"password"	=> 0x0040,
			"admin"		=> 0x8000,	// admin
			);
	return $perms;
}


/**
  The permission engine.

  This function decides wether a specific function is allowed or not
  depending the rights of the current user.

  @param $dir	Directory in which  the action should happen. If this parameter is
  		NULL the engine relys on the global permissions of the user.
  		
  @param $file	File on which the action should happen, if this parameter is NULL
  		the permission engine relys on the permission of the directory.

  @param $action
  		One ore more action of the action set (see permissions_get) which sould
  		be exectuted.
		More actions are seperated by a &.
		
		Example:

		"read&write&password" grants only if user has all three permissions

  @return	true if the action is granted, false otherwise

  @remarks	Until now the permission engine does not support directory or
  		file based actions, so only the global actions are treated. The paramers
		$dir and $file are ignored. This is for later use. However, if possible,
		provide the $dir and $file parameters so the code does not have to
		be chaned if the permission engine will support this features in
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,10 +29,10 @@
   depending the rights of the current user.
 
   @param $dir	Directory in which  the action should happen. If this parameter is
-  		NULL the engine relys on the global permissions of the user.
+  		NULL the engine checks the global permissions of the user.
   		
   @param $file	File on which the action should happen, if this parameter is NULL
-  		the permission engine relys on the permission of the directory.
+  		the permission engine checks the user permissions on the directory.
 
   @param $action
   		One ore more action of the action set (see permissions_get) which sould
```
