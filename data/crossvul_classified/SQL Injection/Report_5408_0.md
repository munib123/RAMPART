# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5408_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5408_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

class navigationController extends expController {
    public $basemodel_name = 'section';
    public $useractions = array(
        'showall' => 'Show Navigation',
        'breadcrumb' => 'Breadcrumb',
    );
//    protected $remove_permissions = array(
//        'configure',
//        'create',
//        'delete',
//        'edit'
//    );
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
        'files',
        'pagination',
        'rss',
        'tags',
        'twitter',
    );  // all options: ('aggregation','categories','comments','ealerts','facebook','files','pagination','rss','tags','twitter',)

    static function displayname() { return gt("Navigation"); }

    static function description() { return gt("Places navigation links/menus on the page."); }

    static function isSearchable() { return true; }

    function searchName() { return gt('Webpage'); }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,8 @@
         'move'      => 'Move Page',
         'remove'    => 'Remove Page',
         'reparent'    => 'Reparent Page',
+        'dragndroprerank'    => 'Rerank Page',
+        'dragndroprerank2'    => 'Rerank Page',
     );
     public $remove_configs = array(
         'aggregation',
@@ -858,8 +860,8 @@
     public static function DragnDropReRank() {
         global $db, $router;
 
-        $move   = $router->params['move'];
-        $target = $router->params['target'];
+        $move   = intval($router->params['move']);
+        $target = intval($router->params['target']);
         $type   = $router->params['type'];
         $targSec = $db->selectObject("section","id=".$target);
 //        $targSec  = new section($target);
```
