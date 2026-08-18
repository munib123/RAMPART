# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 619_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `619_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 892-932 of the vulnerable file.

				$this->response->download('MISP.report.json');
				return $this->response;
			}

			$priorities = array(0 => 'Critical', 1 => 'Recommended', 2 => 'Optional', 3 => 'Deprecated');
			$this->set('priorities', $priorities);
			$this->set('workerIssueCount', $workerIssueCount);
			$priorityErrorColours = array(0 => 'red', 1 => 'yellow', 2 => 'green');
			$this->set('priorityErrorColours', $priorityErrorColours);
			$this->set('phpversion', phpversion());
			$this->set('phpmin', $this->phpmin);
			$this->set('phprec', $this->phprec);
		}
	}

	public function startWorker($type) {
		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException();
		$validTypes = array('default', 'email', 'scheduler', 'cache', 'prio');
		if (!in_array($type, $validTypes)) throw new MethodNotAllowedException('Invalid worker type.');
		$prepend = '';
		if (Configure::read('MISP.rh_shell_fix')) $prepend = 'export PATH=$PATH:"/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin"; ';
		if ($type != 'scheduler') shell_exec($prepend . APP . 'Console' . DS . 'cake CakeResque.CakeResque start --interval 5 --queue ' . $type .' > /dev/null 2>&1 &');
		else shell_exec($prepend . APP . 'Console' . DS . 'cake CakeResque.CakeResque startscheduler -i 5 > /dev/null 2>&1 &');
		$this->redirect('/servers/serverSettings/workers');
	}

	public function stopWorker($pid) {
		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException();
		$this->Server->killWorker($pid, $this->Auth->user());
		$this->redirect('/servers/serverSettings/workers');
	}

	private function __checkVersion() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		try {
			$HttpSocket = $syncTool->setupHttpSocket();
			$response = $HttpSocket->get('https://api.github.com/repos/MISP/MISP/tags');
			$tags = $response->body;
		} catch (Exception $e) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -909,7 +909,6 @@
 		$validTypes = array('default', 'email', 'scheduler', 'cache', 'prio');
 		if (!in_array($type, $validTypes)) throw new MethodNotAllowedException('Invalid worker type.');
 		$prepend = '';
-		if (Configure::read('MISP.rh_shell_fix')) $prepend = 'export PATH=$PATH:"/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin"; ';
 		if ($type != 'scheduler') shell_exec($prepend . APP . 'Console' . DS . 'cake CakeResque.CakeResque start --interval 5 --queue ' . $type .' > /dev/null 2>&1 &');
 		else shell_exec($prepend . APP . 'Console' . DS . 'cake CakeResque.CakeResque startscheduler -i 5 > /dev/null 2>&1 &');
 		$this->redirect('/servers/serverSettings/workers');
@@ -1125,12 +1124,6 @@
 		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException();
 		$this->Server->workerRemoveDead($this->Auth->user());
 		$prepend = '';
-		if (Configure::read('MISP.rh_shell_fix')) {
-			$prepend = 'export PATH=$PATH:"/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin"; ';
-			if (Configure::read('MISP.rh_shell_fix_path')) {
-				if ($this->Server->testForPath(Configure::read('MISP.rh_shell_fix_path'))) $prepend = Configure::read('MISP.rh_shell_fix_path');
-			}
-		}
 		shell_exec($prepend . APP . 'Console' . DS . 'worker' . DS . 'start.sh > /dev/null 2>&1 &');
 		$this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'workers'));
 	}
```
