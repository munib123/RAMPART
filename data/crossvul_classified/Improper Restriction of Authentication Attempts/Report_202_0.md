# CrossVul Fix Pair: Improper Restriction of Excessive Authentication Attempts in php
**Pair ID:** 202_0
**Vulnerability Class:** Improper Restriction of Authentication Attempts
**CWE:** CWE-307
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `202_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Excessive Authentication Attempts - The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame, making it more susceptible to brute force attacks.

## Vulnerable Code
```php
Lines 839-882 of the vulnerable file.

		}
		$this->Flash->error(__('User was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

	public function updateLoginTime() {
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This feature is only accessible via POST requests');
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

	public function login() {
		$this->Bruteforce = ClassRegistry::init('Bruteforce');
		if ($this->request->is('post') && isset($this->request->data['User']['email'])) {
			if ($this->Bruteforce->isBlacklisted($_SERVER['REMOTE_ADDR'], $this->request->data['User']['email'])) {
				throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait ' . Configure::read('SecureAuth.expire') . ' seconds and try again.');
			}
		}
		if ($this->request->is('post') || $this->request->is('put')) {
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -856,13 +856,13 @@
 	}
 
 	public function login() {
-		$this->Bruteforce = ClassRegistry::init('Bruteforce');
-		if ($this->request->is('post') && isset($this->request->data['User']['email'])) {
-			if ($this->Bruteforce->isBlacklisted($_SERVER['REMOTE_ADDR'], $this->request->data['User']['email'])) {
-				throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait ' . Configure::read('SecureAuth.expire') . ' seconds and try again.');
-			}
-		}
 		if ($this->request->is('post') || $this->request->is('put')) {
+			$this->Bruteforce = ClassRegistry::init('Bruteforce');
+			if (!empty($this->request->data['User']['email'])) {
+				if ($this->Bruteforce->isBlacklisted($_SERVER['REMOTE_ADDR'], $this->request->data['User']['email'])) {
+					throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait ' . Configure::read('SecureAuth.expire') . ' seconds and try again.');
+				}
+			}
 			// Check the length of the user's authkey
 			$userPass = $this->User->find('first', array(
 				'conditions' => array('User.email' => $this->request->data['User']['email']),
```
