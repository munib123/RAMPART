# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5404_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5404_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

 */
/** @define "BASE" "../../../.." */

class usersController extends expController {
    public $basemodel_name = 'user';
//    protected $remove_permissions = array(
//        'create',
//        'edit'
//    );
    protected $manage_permissions = array(
        'toggle_extension' => 'Activate Extensions',
        'kill_session'     => 'End Sessions',
        'boot_user'        => 'Boot Users',
        'userperms'        => 'User Permissions',
        'groupperms'       => 'Group Permissions',
        'import'           => 'Import Users',
        'export'           => 'Export Users',
        'update'           => 'Update Users',
        'show'             => 'Show User',
        'showall'          => 'Show Users',
    );

    static function displayname() {
        return gt("User Manager");
    }

    static function description() {
        return gt("This is the user management module. It allows for creating user, editing user, etc.");
    }

    static function hasSources() {
        return false;
    }

    static function hasContent() {
        return false;
    }

    static function canImportData() {
        return true;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,7 @@
         'update'           => 'Update Users',
         'show'             => 'Show User',
         'showall'          => 'Show Users',
+        'getUsersByJSON'   => 'Get Users',
     );
 
     static function displayname() {
```
