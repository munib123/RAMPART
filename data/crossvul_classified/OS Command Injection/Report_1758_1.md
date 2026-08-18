# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 1758_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1758_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 26-74 of the vulnerable file.

	/**
	 * @param Server $server
	 * @param string $name
	 */
	public function __construct($server, $name) {
		$this->server = $server;
		$this->name = $name;
		$this->state = new NativeState();
	}

	/**
	 * @throws \Icewind\SMB\Exception\ConnectionException
	 * @throws \Icewind\SMB\Exception\AuthenticationException
	 * @throws \Icewind\SMB\Exception\InvalidHostException
	 */
	protected function connect() {
		if ($this->state and $this->state instanceof NativeShare) {
			return;
		}

		$user = $this->server->getUser();
		if (strpos($user, '/')) {
			list($workgroup, $user) = explode('/', $user);
		} elseif (strpos($user, '\\')) {
			list($workgroup, $user) = explode('\\', $user);
		} else {
			$workgroup = null;
		}
		$this->state->init($workgroup, $user, $this->server->getPassword());
	}

	/**
	 * Get the name of the share
	 *
	 * @return string
	 */
	public function getName() {
		return $this->name;
	}

	private function buildUrl($path) {
		$url = sprintf('smb://%s/%s', $this->server->getHost(), $this->name);
		if ($path) {
			$path = trim($path, '/');
			$url .= '/';
			$url .= implode('/', array_map('rawurlencode', explode('/', $path)));
		}
		return $url;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,15 +43,7 @@
 			return;
 		}
 
-		$user = $this->server->getUser();
-		if (strpos($user, '/')) {
-			list($workgroup, $user) = explode('/', $user);
-		} elseif (strpos($user, '\\')) {
-			list($workgroup, $user) = explode('\\', $user);
-		} else {
-			$workgroup = null;
-		}
-		$this->state->init($workgroup, $user, $this->server->getPassword());
+		$this->state->init($this->server->getWorkgroup(), $this->server->getUser(), $this->server->getPassword());
 	}
 
 	/**
```
