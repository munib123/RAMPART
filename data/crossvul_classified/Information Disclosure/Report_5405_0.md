# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5405_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5405_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

# GPL: http://www.gnu.org/licenses/gpl.txt
#
##################################################

/**
 * @package Modules
 * @subpackage Controllers
 */

class addressController extends expController {
//	public $useractions = array(
//        'myaddressbook'=>'Show my addressbook'
//    );
    protected $remove_permissions = array(
        'create',
        'edit',
        'delete'
    );
    protected $manage_permissions = array(
//        'import' => 'Import External Addresses',
        'process' => 'Import External Addresses'
    );
    public $requires_login = array(
        'myaddressbook'=>'You must be logged in to perform this action',
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
    ); // all options: ('aggregation','categories','comments','ealerts','facebook','files','module_title','pagination','rss','tags','twitter',)

    static function displayname() { return gt("Addresses"); }
    static function description() { return gt("Display and manage addresses of users on your site."); }
    static function canImportData() { return true;}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,9 +32,16 @@
     );
     protected $manage_permissions = array(
 //        'import' => 'Import External Addresses',
-        'process' => 'Import External Addresses'
+        'process' => 'Import External Addresses',
+        'edit_country' => 'Edit Country',
+        'delete_country' => 'Delete Country',
+        'update_country' => 'Update Country',
+        'edit_region' => 'Edit Region',
+        'delete_region' => 'Delete Region',
+        'update_region' => 'Update Region',
     );
     public $requires_login = array(
+        'edit'=>'You must be logged in to perform this action',
         'myaddressbook'=>'You must be logged in to perform this action',
     );
 	public $remove_configs = array(
@@ -65,8 +72,18 @@
 
     public function edit()
     {
-        if((isset($this->params['id']))) $record = new address(intval($this->params['id']));
-        else $record = null;
+        global $user;
+
+        $id = !empty($this->params['id']) ? $this->params['id'] : null;
+
+        // check to see if we should be editing.  You either need to be an admin, or editing own account.
+        if ($user->isAdmin() || ($user->id == $id)) {
+            $record = new address($id);
+        } else {
+            flash('error', gt('You do not have the proper permissions to edit this address'));
+            expHistory::back();
+        }
+
         $config = ecomconfig::getConfig('address_allow_admins_all');
         assign_to_template(array(
             'record'=>$record,
@@ -83,7 +100,7 @@
 		global $user;
 
 		// check if the user is logged in.
-		expQueue::flashIfNotLoggedIn('message',gt('You must be logged in to manage your address book.'));
+		expQueue::flashIfNotLoggedIn('message',gt('You must be logged in to manage your address book.'));  //fixme is this redundant to common routine?
         if (!$user->isAdmin() && $this->params['user_id'] != $user->id) {
             unset($this->params['user_id']);
         }
```
