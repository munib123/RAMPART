# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 1088_2
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1088_2`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 27-72 of the vulnerable file.

    );

    public $uses = array('Server', 'Event');

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions[] = 'getApiInfo';
        // permit reuse of CSRF tokens on some pages.
        switch ($this->request->params['action']) {
            case 'push':
            case 'pull':
            case 'getVersion':
            case 'testConnection':
                $this->Security->csrfUseOnce = false;
        }
    }

    public function index()
    {
        if (!$this->_isSiteAdmin()) {
            if (!$this->userRole['perm_sync'] && !$this->userRole['perm_admin']) {
                $this->redirect(array('controller' => 'events', 'action' => 'index'));
            }
            $this->paginate['conditions'] = array('Server.org_id LIKE' => $this->Auth->user('org_id'));
        }
        if ($this->_isRest()) {
            $params = array(
                'recursive' => -1,
                'contain' => array(
                        'User' => array(
                                'fields' => array('User.id', 'User.org_id', 'User.email'),
                        ),
                        'Organisation' => array(
                                'fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid', 'Organisation.nationality', 'Organisation.sector', 'Organisation.type'),
                        ),
                        'RemoteOrg' => array(
                                'fields' => array('RemoteOrg.id', 'RemoteOrg.name', 'RemoteOrg.uuid', 'RemoteOrg.nationality', 'RemoteOrg.sector', 'RemoteOrg.type'),
                        ),
                ),
            );
            $servers = $this->Server->find('all', $params);
            $servers = $this->Server->attachServerCacheTimestamps($servers);
            return $this->RestResponse->viewData($servers, $this->response->type());
        } else {
            $servers = $this->paginate();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,12 +44,6 @@
 
     public function index()
     {
-        if (!$this->_isSiteAdmin()) {
-            if (!$this->userRole['perm_sync'] && !$this->userRole['perm_admin']) {
-                $this->redirect(array('controller' => 'events', 'action' => 'index'));
-            }
-            $this->paginate['conditions'] = array('Server.org_id LIKE' => $this->Auth->user('org_id'));
-        }
         if ($this->_isRest()) {
             $params = array(
                 'recursive' => -1,
@@ -2089,4 +2083,28 @@
             }
         }
     }
+
+    public function resetRemoteAuthKey($id)
+    {
+        if (!$this->request->is('post')) {
+            throw new MethodNotAllowedException(__('This endpoint expects POST requests.'));
+        }
+        $result = $this->Server->resetRemoteAuthkey($id);
+        if ($result !== true) {
+            if (!$this->_isRest()) {
+                $this->Flash->error($result);
+                $this->redirect(array('action' => 'index'));
+            } else {
+                return $this->RestResponse->saveFailResponse('Servers', 'resetRemoteAuthKey', $id, $message, $this->response->type());
+            }
+        } else {
+            $message = __('API key updated.');
+            if (!$this->_isRest()) {
+                $this->Flash->success($message);
+                $this->redirect(array('action' => 'index'));
+            } else {
+                return $this->RestResponse->saveSuccessResponse('Servers', 'resetRemoteAuthKey', $message, $this->response->type());
+            }
+        }
+    }
 }
```
