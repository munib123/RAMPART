# CrossVul Fix Pair: Time-of-check Time-of-use (TOCTOU) Race Condition in php
**Pair ID:** 4661_0
**Vulnerability Class:** Time-of-check Time-of-use (TOCTOU) Race Condition
**CWE:** CWE-367
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4661_0`)

## Vulnerability Information & PoC

## Description
Time-of-check Time-of-use (TOCTOU) Race Condition - This weakness can be security-relevant when an attacker can influence the state of the resource between check and use.

## Vulnerable Code
```php
Lines 1049-1089 of the vulnerable file.

            throw new MethodNotAllowedException('This feature is only accessible via POST requests');
        }
        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => array('User.id' => $this->Auth->user('id'))
        ));
        $this->User->id = $this->Auth->user('id');
        $this->User->saveField('last_login', time());
        $this->User->saveField('current_login', time());
        $user = $this->User->getAuthUser($user['User']['id']);
        $this->Auth->login($user);
        $this->redirect(array('Controller' => 'User', 'action' => 'dashboard'));
    }

    public function login()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->Bruteforce = ClassRegistry::init('Bruteforce');
            if (!empty($this->request->data['User']['email'])) {
                if ($this->Bruteforce->isBlacklisted($_SERVER['REMOTE_ADDR'], $this->request->data['User']['email'])) {
                    throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait ' . Configure::read('SecureAuth.expire') . ' seconds and try again.');
                }
            }
            // Check the length of the user's authkey
            $userPass = $this->User->find('first', array(
                'conditions' => array('User.email' => $this->request->data['User']['email']),
                'fields' => array('User.password'),
                'recursive' => -1
            ));
            if (!empty($userPass) && strlen($userPass['User']['password']) == 40) {
                $this->AdminSetting = ClassRegistry::init('AdminSetting');
                $db_version = $this->AdminSetting->find('all', array('conditions' => array('setting' => 'db_version')));
                $versionRequirementMet = $this->User->checkVersionRequirements($db_version[0]['AdminSetting']['value'], '2.4.77');
                if ($versionRequirementMet) {
                    $passwordToSave = $this->request->data['User']['password'];
                }
                unset($this->Auth->authenticate['Form']['passwordHasher']);
                $this->Auth->constructAuthenticate();
            }
        }
        if ($this->Auth->login()) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1066,6 +1066,7 @@
             $this->Bruteforce = ClassRegistry::init('Bruteforce');
             if (!empty($this->request->data['User']['email'])) {
                 if ($this->Bruteforce->isBlacklisted($_SERVER['REMOTE_ADDR'], $this->request->data['User']['email'])) {
+                    $expire = Configure::check('SecureAuth.expire') ? Configure::read('SecureAuth.expire') : 300;
                     throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait ' . Configure::read('SecureAuth.expire') . ' seconds and try again.');
                 }
             }
@@ -1116,7 +1117,7 @@
                 $this->Session->delete('Message.auth');
             }
             // don't display "invalid user" before first login attempt
-            if ($this->request->is('post')) {
+            if ($this->request->is('post') || $this->request->is('put')) {
                 $this->Flash->error(__('Invalid username or password, try again'));
                 if (isset($this->request->data['User']['email'])) {
                     $this->Bruteforce->insert($_SERVER['REMOTE_ADDR'], $this->request->data['User']['email']);
```
