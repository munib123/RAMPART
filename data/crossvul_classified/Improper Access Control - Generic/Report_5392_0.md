# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5392_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5392_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 36-76 of the vulnerable file.


    // $permissions used to restrict access to module's actions/methods
    protected $permissions = array(  // standard set of permissions for all modules unless add'ed or remove'd
        'manage'    => 'Manage',
        'configure' => 'Configure',
        'create'    => 'Create',
        'edit'      => 'Edit',
        'delete'    => 'Delete',
    );
    protected $m_permissions = array(  // standard set of actions requiring manage permission for all modules
        'activate'  => 'Activate',
        'approve'   => 'Approve',
        'merge'     => 'Merge',
        'rerank'    => 'ReRank',
        'import'    => 'Import Items',
        'export'    => 'Export Items'
    );
    protected $remove_permissions = array();  // $permissions not applicable for this module from above list
    protected $add_permissions = array();  // additional $permissions processed and visible  for this module
    protected $manage_permissions = array();  // additional actions requiring manage permission in addition to $m_permissions
    public $requires_login = array();  // actions/methods which ONLY require user be logged in to access...$permissions take priority

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
     * @param array $params
     *
     * @return expController
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,7 @@
     protected $remove_permissions = array();  // $permissions not applicable for this module from above list
     protected $add_permissions = array();  // additional $permissions processed and visible  for this module
     protected $manage_permissions = array();  // additional actions requiring manage permission in addition to $m_permissions
-    public $requires_login = array();  // actions/methods which ONLY require user be logged in to access...$permissions take priority
+    public $requires_login = array();  // actions/methods (lower case ONLY) which ONLY require user be logged in to access...$permissions take priority
 
     public $filepath = ''; // location of this controller's files
     public $viewpath = ''; // location of this controllers views; defaults to controller file location
```
