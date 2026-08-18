# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 1758_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1758_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 7-52 of the vulnerable file.


namespace Icewind\SMB;

class NativeServer extends Server {
	/**
	 * @var \Icewind\SMB\NativeState
	 */
	protected $state;

	/**
	 * @param string $host
	 * @param string $user
	 * @param string $password
	 */
	public function __construct($host, $user, $password) {
		parent::__construct($host, $user, $password);
		$this->state = new NativeState();
	}

	protected function connect() {
		$user = $this->getUser();
		$workgroup = null;
		if (strpos($user, '/')) {
			list($workgroup, $user) = explode('/', $user);
		}
		$this->state->init($workgroup, $user, $this->getPassword());
	}

	/**
	 * @return \Icewind\SMB\IShare[]
	 * @throws \Icewind\SMB\Exception\AuthenticationException
	 * @throws \Icewind\SMB\Exception\InvalidHostException
	 */
	public function listShares() {
		$this->connect();
		$shares = array();
		$dh = $this->state->opendir('smb://' . $this->getHost());
		while ($share = $this->state->readdir($dh)) {
			if ($share['type'] === 'file share') {
				$shares[] = $this->getShare($share['name']);
			}
		}
		$this->state->closedir($dh);
		return $shares;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,12 +24,7 @@
 	}
 
 	protected function connect() {
-		$user = $this->getUser();
-		$workgroup = null;
-		if (strpos($user, '/')) {
-			list($workgroup, $user) = explode('/', $user);
-		}
-		$this->state->init($workgroup, $user, $this->getPassword());
+		$this->state->init($this->getWorkgroup(), $this->getUser(), $this->getPassword());
 	}
 
 	/**
```
