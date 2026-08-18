# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5392_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5392_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 18-59 of the vulnerable file.


/**
 * @subpackage Controllers
 * @package Modules
 */

class fileController extends expController {
    public $basemodel_name = "expFile";
    protected $remove_permissions = array(
        'delete'
    );
//    protected $manage_permissions = array(
//        'picker'=>'Manage Files',
//        'import'=>'Import',
//        'export'=>'Export',
//    );
    public $requires_login = array(
        'picker'=>'You must be logged in to perform this action',
        'adder'=>'You must be logged in to perform this action',
        'addit'=>'You must be logged in to perform this action',
        'batchDelete'=>'You must be logged in to perform this action',
        'createFolder'=>'You must be logged in to perform this action',
        'deleter'=>'You must be logged in to perform this action',
        'deleteit'=>'You must be logged in to perform this action',
        'edit'=>'You must be logged in to perform this action',
        'quickUpload'=>'You must be logged in to perform this action',
        'upload'=>'You must be logged in to perform this action',
        'uploader'=>'You must be logged in to perform this action',
    );

    static function displayname() { return gt("File Manager"); }
    static function description() { return gt("Add and manage Exponent Files"); }
    static function author() { return "Phillip Ball - OIC Group, Inc"; }

    public function manage_fixPaths() {
        // fixes file directory issues when the old file class was used to save record
        // where the trailing forward slash was not added. This simply checks to see
        // if the trailing / is there, if not, it adds it.

        $file = new expFile();
        $files = $file->find('all');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,12 +35,13 @@
         'picker'=>'You must be logged in to perform this action',
         'adder'=>'You must be logged in to perform this action',
         'addit'=>'You must be logged in to perform this action',
-        'batchDelete'=>'You must be logged in to perform this action',
-        'createFolder'=>'You must be logged in to perform this action',
+        'batchdelete'=>'You must be logged in to perform this action',
+        'createfolder'=>'You must be logged in to perform this action',
+        'delete'=>'You must be logged in to perform this action',
         'deleter'=>'You must be logged in to perform this action',
         'deleteit'=>'You must be logged in to perform this action',
         'edit'=>'You must be logged in to perform this action',
-        'quickUpload'=>'You must be logged in to perform this action',
+        'quickupload'=>'You must be logged in to perform this action',
         'upload'=>'You must be logged in to perform this action',
         'uploader'=>'You must be logged in to perform this action',
     );
```
