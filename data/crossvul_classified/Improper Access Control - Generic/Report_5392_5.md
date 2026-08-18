# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5392_5
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5392_5`)

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
 * @package    Modules
 */
class navigationController extends expController {
    public $basemodel_name = 'section';
    public $useractions = array(
        'showall' => 'Show Navigation',
        'breadcrumb' => 'Breadcrumb',
    );
    protected $remove_permissions = array(
//        'configure',
//        'create',
//        'delete',
//        'edit'
    );
    protected $add_permissions = array(
        'manage'    => 'Manage',
        'view'      => "View Page"
    );
    protected $manage_permissions = array(
        'move'      => 'Move Page',
        'remove'    => 'Remove Page',
        'reparent'    => 'Reparent Page',
    );
    public $remove_configs = array(
        'aggregation',
        'categories',
        'comments',
        'ealerts',
        'facebook',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,12 +25,12 @@
         'showall' => 'Show Navigation',
         'breadcrumb' => 'Breadcrumb',
     );
-    protected $remove_permissions = array(
+//    protected $remove_permissions = array(
 //        'configure',
 //        'create',
 //        'delete',
 //        'edit'
-    );
+//    );
     protected $add_permissions = array(
         'manage'    => 'Manage',
         'view'      => "View Page"
```
