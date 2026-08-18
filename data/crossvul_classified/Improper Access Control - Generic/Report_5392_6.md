# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5392_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5392_6`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.

#
# Exponent is free software; you can redistribute
# it and/or modify it under the terms of the GNU
# General Public License as published by the Free
# Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# GPL: http://www.gnu.org/licenses/gpl.txt
#
##################################################

/**
 * @subpackage Controllers
 * @package Modules
 */

class pixidouController extends expController {
	public $cacheDir = "tmp/pixidou/";
    public $requires_login = array(
        'editor'=>'You must be logged in to perform this action',
        'exitEditor'=>'You must be logged in to perform this action',
    );

    static function displayname() { return gt("Pixidou Image Editor"); }
    static function description() { return gt("Add and manage Exponent Files"); }
    static function author() { return "Phillip Ball - OIC Group, Inc"; }

    static function hasSources()
    {
        return false;
    }

    function editor() {
        global $user;

        $file = new expFile($this->params['id']);

        $canSaveOg = $user->id==$file->poster || $user->isSuperAdmin() ? 1 : 0 ;
	    if (file_exists(BASE . $file->directory . $file->filename)) {
			$file->copyToDirectory(BASE . $this->cacheDir);
			assign_to_template(array(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
 	public $cacheDir = "tmp/pixidou/";
     public $requires_login = array(
         'editor'=>'You must be logged in to perform this action',
-        'exitEditor'=>'You must be logged in to perform this action',
+        'exiteditor'=>'You must be logged in to perform this action',
     );
 
     static function displayname() { return gt("Pixidou Image Editor"); }
```
