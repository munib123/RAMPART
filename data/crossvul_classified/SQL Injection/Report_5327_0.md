# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5327_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5327_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 24-64 of the vulnerable file.


abstract class expController {
    protected $classname = ''; // full controller name w/ 'Controller' suffix
    public $baseclassname = ''; // root controller name w/o 'Controller' suffix
    public $classinfo = null; // holds reflection class of class
//    public $module_name = '';       //FIXME not used and not actually set right index needed of -3 instead of -2 below
//    protected $basemodel = null;    //FIXME never used, $basemodel_name replaced?
    public $basemodel_name = ''; // holds classname of base model associated w/ this controller
    public $model_table = ''; // holds table name for base model

    public $useractions = array(); // available (displayed) user actions/methods for this module
    public $remove_configs = array(); // all options: ('aggregation','categories','comments','ealerts','facebook','files','module_title','pagination','rss','tags','twitter',)

    // $permissions used to restrict access to module's actions/methods
    protected $permissions = array(  // standard set of permissions for all modules unless add'ed or remove'd
        'manage'    => 'Manage',
        'configure' => 'Configure',
        'create'    => 'Create',
        'edit'      => 'Edit',
        'delete'    => 'Delete',
        'approve'  => 'Approval',
    );
    protected $remove_permissions = array();  // $permissions not applicable for this module from above list
    protected $add_permissions = array();  // additional $permissions processed for this module
    public $requires_login = array(); // actions/methods which ONLY require user be logged in to access...$permissions take priority

    public $filepath = ''; // location of this controller's files
    public $viewpath = ''; // location of this controllers views; defaults to controller file location
    public $relative_viewpath = ''; // relative location of controller's views
    public $asset_path = ''; // location of this controller's assets; defaults to controller file location

    public $config = array(); // holds module configuration settings
    public $params = array(); // holds sanitized parameters passed to module
    public $loc = null; // module location object

    public $codequality = 'stable'; // code's level of stability

    public $rss_is_podcast = false;

    /**
     * @param null  $src
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,11 +41,19 @@
         'create'    => 'Create',
         'edit'      => 'Edit',
         'delete'    => 'Delete',
-        'approve'  => 'Approval',
+    );
+    protected $m_permissions = array(  // standard set of actions requiring manage permission for all modules
+        'activate'  => 'Activate',
+        'approve'   => 'Approve',
+        'merge'     => 'Merge',
+        'rerank'    => 'ReRank',
+        'import'    => 'Import Items',
+        'export'    => 'Export Items'
     );
     protected $remove_permissions = array();  // $permissions not applicable for this module from above list
-    protected $add_permissions = array();  // additional $permissions processed for this module
-    public $requires_login = array(); // actions/methods which ONLY require user be logged in to access...$permissions take priority
+    protected $add_permissions = array();  // additional $permissions processed and visible  for this module
+    protected $manage_permissions = array();  // additional actions requiring manage permission in addition to $m_permissions
+    public $requires_login = array();  // actions/methods which ONLY require user be logged in to access...$permissions take priority
 
     public $filepath = ''; // location of this controller's files
     public $viewpath = ''; // location of this controllers views; defaults to controller file location
@@ -131,6 +139,8 @@
         $this->config = $config->config;
 
         $this->params = $params;
+        if (ENABLE_WORKFLOW)
+            $this->permissions = array_merge($this->permissions, array('approve'=>'Approval'));
     }
 
     /**
@@ -294,7 +304,7 @@
         $modelname = $this->basemodel_name;
 
         // get the tag being passed
-        $tag = new expTag($this->params['tag']);
+        $tag = new expTag(expString::escape($this->params['tag']));
 
         // find all the id's of the portfolios for this module
         $item_ids = $db->selectColumn($modelname, 'id', $this->aggregateWhereClause());
@@ -328,7 +338,7 @@
         assign_to_template(array(
             'page'        => $page,
             'items'       => $page->records,
-            'moduletitle' => ucfirst($modelname) . ' ' . gt('items tagged with') . ' "' . expString::sanitize($this->params['tag']) . '"',
+            'moduletitle' => ucfirst($modelname) . ' ' . gt('items tagged with') . ' "' . expString::escape($this->params['tag']) . '"',
             'rank'        => ($order === 'rank') ? 1 : 0
         ));
     }
@@ -454,7 +464,7 @@
         if (isset($this->params['id'])) {
             $id = $this->params['id'];
         } elseif (isset($this->params['title'])) {
-            $id = $this->params['title'];
+            $id = expString::escape($this->params['title']);
         }
 
         $record = new $modelname($id);
@@ -485,6 +495,7 @@
         $modelname = $this->basemodel_name;
         // first we'll check to see if this matches the sef_url field...if not then we'll look for the
         // title field
+        $this->params['title'] = expString::escape($this->params['title']);  // escape title to prevent sql injection
         $record = $this->$modelname->find('first', "sef_url='" . $this->params['title'] . "'");
         if (!is_object($record)) {
             $record = $this->$modelname->find('first', "title='" . $this->params['title'] . "'");
@@ -1012,7 +1023,7 @@
     public function rss() {
         require_once(BASE . 'external/feedcreator.class.php');
 
-        $id = isset($this->params['title']) ? $this->params['title'] : (isset($this->params['id']) ? $this->params['id'] : null);
+        $id = isset($this->params['title']) ? expString::escape($this->params['title']) : (isset($this->params['id']) ? $this->params['id'] : null);
         if (empty($id)) {
             $module = !empty($this->params['module']) ? $this->params['module'] : $this->params['controller'];
             $id = array('module' => $module, 'src' => $this->params['src']);
@@ -1143,7 +1154,7 @@
     }
 
     /**
-     * permission functions to aggregate a module's permissions based on add/remove permissions
+     * permission functions to aggregate a module's visible permissions based on add/remove permissions
      *
      * @return array
      */
@@ -1154,6 +1165,21 @@
             if (!in_array($perm, $this->remove_permissions)) $perms[$perm] = $name;
         }
         $perms = array_merge($perms, $this->add_permissions);
+        return $perms;
+    }
+
+    /**
+     * permission functions to aggregate a module's permissions based on add/remove and manage permissions
+     *
+     * @return array
+     */
+    public function permissions_all() {
+        //set the permissions array
+        $perms = array();
+        foreach ($this->permissions as $perm => $name) {
+            if (!in_array($perm, $this->remove_permissions)) $perms[$perm] = $name;
+        }
+        $perms = array_merge($perms, $this->m_permissions, $this->add_permissions, $this->manage_permissions);
         return $perms;
     }
 
```
