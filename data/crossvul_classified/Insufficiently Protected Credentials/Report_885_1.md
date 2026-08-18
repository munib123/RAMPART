# CrossVul Fix Pair: Credentials Management Errors in php
**Pair ID:** 885_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `885_1`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```php
Lines 2-42 of the vulnerable file.

App::uses('AppController', 'Controller');

class UsersController extends AppController
{
    public $newkey;

    public $components = array(
            'Security',
            'Email',
            'RequestHandler'
    );

    public $paginate = array(
            'limit' => 60,
            'recursive' => -1,
            'order' => array(
                    'Organisation.name' => 'ASC'
            ),
            'contain' => array(
                'Organisation' => array('id', 'name'),
                'Role' => array('id', 'name', 'perm_auth')
            )
    );

    public $helpers = array('Js' => array('Jquery'));

    public function beforeFilter()
    {
        parent::beforeFilter();

        // what pages are allowed for non-logged-in users
        $this->Auth->allow('login', 'logout');
    }

    public function view($id = null)
    {
        if ("me" == $id) {
            $id = $this->Auth->user('id');
        }
        if (!$this->_isSiteAdmin() && $this->Auth->user('id') != $id) {
            throw new NotFoundException(__('Invalid user or not authorised.'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,7 +19,7 @@
             ),
             'contain' => array(
                 'Organisation' => array('id', 'name'),
-                'Role' => array('id', 'name', 'perm_auth')
+                'Role' => array('id', 'name', 'perm_auth', 'perm_site_admin')
             )
     );
 
@@ -350,11 +350,16 @@
                     ),
                     'contain' => array(
                             'Organisation' => array('id', 'name'),
-                            'Role' => array('id', 'name', 'perm_auth')
+                            'Role' => array('id', 'name', 'perm_auth', 'perm_site_admin')
                     )
             ));
             foreach ($users as $key => $value) {
-                unset($users['User']['password']);
+                if (empty($this->Auth->user('Role')['perm_site_admin'])) {
+                    if ($value['Role']['perm_site_admin']) {
+                        $users[$key]['User']['authkey'] = __('Redacted');
+                    }
+                }
+                unset($users[$key]['User']['password']);
             }
             return $this->RestResponse->viewData($users, $this->response->type());
         } else {
@@ -366,7 +371,13 @@
             } else {
                 $conditions['User.org_id'] = $this->Auth->user('org_id');
                 $this->paginate['conditions']['AND'][] = $conditions;
-                $this->set('users', $this->paginate());
+                $users = $this->paginate();
+                foreach ($users as $key => $value) {
+                    if ($value['Role']['perm_site_admin']) {
+                        $users[$key]['User']['authkey'] = __('Redacted');
+                    }
+                }
+                $this->set('users', $users);
             }
             if ($this->request->is('ajax')) {
                 $this->autoRender = false;
@@ -462,6 +473,9 @@
             $user['User']['fingerprint'] = !empty($pgpDetails[4]) ? $pgpDetails[4] : 'N/A';
         }
         $user['User']['orgAdmins'] = $this->User->getOrgAdminsForOrg($user['User']['org_id'], $user['User']['id']);
+        if (empty($this->Auth->user('Role')['perm_site_admin']) && !(empty($user['Role']['perm_site_admin']))) {
+            $user['User']['authkey'] = __('Redacted');
+        }
         $this->set('user', $user);
         if (!$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org_id') == $user['User']['org_id'])) {
             throw new MethodNotAllowedException();
@@ -694,9 +708,10 @@
         $params = array();
         $allowedRole = '';
         $userToEdit = $this->User->find('first', array(
-                'conditions' => array('id' => $id),
+                'conditions' => array('User.id' => $id),
                 'recursive' => -1,
-                'fields' => array('id', 'role_id', 'email', 'org_id'),
+                'fields' => array('User.id', 'User.role_id', 'User.email', 'User.org_id', 'Role.perm_site_admin'),
+                'contain' => array('Role')
         ));
         if (!$this->_isSiteAdmin()) {
             // Org admins should be able to select the role that is already assigned to an org user when editing them.
@@ -706,8 +721,8 @@
             // MISP automatically chooses the first available option for the user as the selected setting (usually user)
             // Org admin is downgraded to a user
             // Now we make an exception for the already assigned role, both in the form and the actual edit.
-            if ($userToEdit['User']['org_id'] != $this->Auth->user('org_id')) {
-                throw new Exception('Invalid user');
+            if ($userToEdit['User']['org_id'] != $this->Auth->user('org_id') || !empty($userToEdit['Role']['perm_site_admin'])) {
+                throw new NotFoundException(__('Invalid user'));
             }
             $allowedRole = $userToEdit['User']['role_id'];
             $params = array('conditions' => array(
```
