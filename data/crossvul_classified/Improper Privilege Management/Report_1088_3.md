# CrossVul Fix Pair: Improper Privilege Management in php
**Pair ID:** 1088_3
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1088_3`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```php
Lines 194-234 of the vulnerable file.

                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('Users', 'change_pw', false, $message, $this->response->type());
                    }
                    $abortPost = true;
                    $this->Flash->info($message);
                }
            }
            if (!$abortPost) {
                // What fields should be saved (allowed to be saved)
                $user['User']['change_pw'] = 0;
                $user['User']['password'] = $this->request->data['User']['password'];
                if ($this->_isRest()) {
                    $user['User']['confirm_password'] = $this->request->data['User']['password'];
                } else {
                    $user['User']['confirm_password'] = $this->request->data['User']['confirm_password'];
                }
                $temp = $user['User']['password'];
                // Save the data
                if ($this->User->save($user)) {
                    $message = __('Password Changed.');
                    $this->__extralog("change_pw");
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveSuccessResponse('User', 'change_pw', false, $this->response->type(), $message);
                    }
                    $this->Flash->success($message);
                    $this->_refreshAuth();
                    $this->redirect(array('action' => 'view', $id));
                } else {
                    $message = __('The password could not be updated. Make sure you meet the minimum password length / complexity requirements.');
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('Users', 'change_pw', false, $message, $this->response->type());
                    }
                    $this->Flash->error($message);
                }
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->describe('Users', 'change_pw', false, $this->response->type());
        }
        $this->loadModel('Server');
        $this->set('complexity', !empty(Configure::read('Security.password_policy_complexity')) ? Configure::read('Security.password_policy_complexity') : $this->Server->serverSettings['Security']['password_policy_complexity']['value']);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -211,7 +211,7 @@
                 // Save the data
                 if ($this->User->save($user)) {
                     $message = __('Password Changed.');
-                    $this->__extralog("change_pw");
+                    $this->User->extralog($this->Auth->user(), "change_pw", null, null, $user);
                     if ($this->_isRest()) {
                         return $this->RestResponse->saveSuccessResponse('User', 'change_pw', false, $this->response->type(), $message);
                     }
@@ -869,7 +869,11 @@
                         $c++;
                     }
                     $fieldsResultStr = substr($fieldsResultStr, 2);
-                    $this->__extralog("edit", "user", $fieldsResultStr);
+                    $user = $this->User->find('first', array(
+                        'recursive' => -1,
+                        'conditions' => array('User.id' => $this->id)
+                    ));
+                    $this->User->extralog($this->Auth->user(), "edit", "user", $fieldsResultStr, $user);
                     if ($this->_isRest()) {
                         $user = $this->User->find('first', array(
                                 'conditions' => array('User.id' => $this->User->id),
@@ -954,7 +958,7 @@
         }
         $fieldsDescrStr = 'User (' . $id . '): ' . $user['User']['email'];
         if ($this->User->delete($id)) {
-            $this->__extralog("delete", $fieldsDescrStr, '');
+            $this->User->extralog($this->Auth->user(), "delete", $fieldsDescrStr, '');
             if ($this->_isRest()) {
                 return $this->RestResponse->saveSuccessResponse('User', 'admin_delete', $id, $this->response->type(), 'User deleted.');
             } else {
@@ -1010,7 +1014,7 @@
             }
         }
         if ($this->Auth->login()) {
-            $this->__extralog("login");
+            $this->User->extralog($this->Auth->user(), "login");
             $this->User->Behaviors->disable('SysLogLogable.SysLogLogable');
             $this->User->id = $this->Auth->user('id');
             $user = $this->User->find('first', array(
@@ -1125,7 +1129,7 @@
     public function logout()
     {
         if ($this->Session->check('Auth.User')) {
-            $this->__extralog("logout");
+            $this->User->extralog($this->Auth->user(), "logout");
         }
         $this->Flash->info(__('Good-Bye'));
         $user = $this->User->find('first', array(
@@ -1140,7 +1144,7 @@
         $this->redirect($this->Auth->logout());
     }
 
-    public function resetauthkey($id = null)
+    public function resetauthkey($id = null, $alert = false)
     {
         if (!$this->_isAdmin() && Configure::read('MISP.disableUserSelfManagement')) {
             throw new MethodNotAllowedException('User self-management has been disabled on this instance.');
@@ -1149,30 +1153,37 @@
             $id = $this->Auth->user('id');
         }
         if (!$this->userRole['perm_auth']) {
-            throw new MethodNotAllowedException('Invalid action.');
-        }
-        $this->User->id = $id;
-        if (!$id || !$this->User->exists($id)) {
-            throw new MethodNotAllowedException('Invalid user.');
-        }
-        $user = $this->User->read();
-        $oldKey = $this->User->data['User']['authkey'];
-        if (!$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org_id') == $this->User->data['User']['org_id']) && ($this->Auth->user('id') != $id)) {
-            throw new MethodNotAllowedException('Invalid user.');
-        }
-        $newkey = $this->User->generateAuthKey();
-        $this->User->saveField('authkey', $newkey);
-        $this->__extralog(
-                'reset_auth_key',
-                'Authentication key for user ' . $user['User']['id'] . ' (' . $user['User']['email'] . ')',
-                $fieldsResult = 'authkey(' . $oldKey . ') => (' . $newkey . ')'
-        );
+            throw new MethodNotAllowedException(__('Invalid action.'));
+        }
+        $newkey = $this->User->resetauthkey($this->Auth->user(), $id, $alert);
+        if ($newkey === false) {
+            throw new MethodNotAllowedException(__('Invalid user.'));
+        }
         if (!$this->_isRest()) {
             $this->Flash->success(__('New authkey generated.', true));
             $this->_refreshAuth();
             $this->redirect($this->referer());
         } else {
             return $this->RestResponse->saveSuccessResponse('User', 'resetauthkey', $id, $this->response->type(), 'Authkey updated: ' . $newkey);
+        }
+    }
+
+    public function resetAllSyncAuthKeys()
+    {
+        if (!$this->request->is('post')) {
+            throw new MethodNotAllowedException(__('This functionality is only accessible via POST requests.'));
+        }
+        $results = $this->User->resetAllSyncAuthKeysRouter($this->Auth->user());
+        if ($results === true) {
+            $message = __('Job initiated.');
+        } else {
+            $message = __('%s authkeys reset, %s could not be reset.', $results['success'], $results['fails']);
+        }
+        if (!$this->_isRest()) {
+            $this->Flash->info($message);
+            $this->redirect($this->referer());
+        } else {
+            return $this->RestResponse->saveSuccessResponse('User', 'resetAllSyncAuthKeys', false, $this->response->type(), $message);
         }
     }
 
@@ -1295,44 +1306,6 @@
         }
         $this->response->file($termsFile, array('download' => true, 'name' => Configure::read('MISP.terms_file')));
         return $this->response;
-    }
-
-    private function __extralog($action = null, $description = null, $fieldsResult = null)
-    {
-        // new data
-        $model = 'User';
-        $modelId = $this->Auth->user('id');
-        if ($action == 'login') {
-            $description = "User (" . $this->Auth->user('id') . "): " . $this->data['User']['email'];
-        } elseif ($action == 'logout') {
-            $description = "User (" . $this->Auth->user('id') . "): " . $this->Auth->user('email');
-        } elseif ($action == 'edit') {
-            $description = "User (" . $this->User->id . "): " . $this->data['User']['email'];
-        } elseif ($action == 'change_pw') {
-            $description = "User (" . $this->User->id . "): " . $this->Auth->user('email');
-            $fieldsResult = "Password changed.";
-        }
-
-        // query
-        $this->Log = ClassRegistry::init('Log');
-        $this->Log->create();
-        $this->Log->save(array(
-            'org' => $this->Auth->user('Organisation')['name'],
-            'model' => $model,
-            'model_id' => $modelId,
-            'email' => $this->Auth->user('email'),
-            'action' => $action,
-            'title' => $description,
-            'change' => isset($fieldsResult) ? $fieldsResult : ''));
-
-        // write to syslogd as well
-        App::import('Lib', 'SysLog.SysLog');
-        $syslog = new SysLog();
-        if (isset($fieldsResult) && $fieldsResult) {
-            $syslog->write('notice', $description . ' -- ' . $action . ' -- ' . $fieldsResult);
-        } else {
-            $syslog->write('notice', $description . ' -- ' . $action);
-        }
     }
 
     // Used for fields_before and fields for audit
```
