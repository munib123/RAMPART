# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 1758_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1758_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 13-53 of the vulnerable file.

class Server {
	const CLIENT = 'smbclient';
	const LOCALE = 'en_US.UTF-8';

	/**
	 * @var string $host
	 */
	protected $host;

	/**
	 * @var string $user
	 */
	protected $user;

	/**
	 * @var string $password
	 */
	protected $password;

	/**
	 * Check if the smbclient php extension is available
	 *
	 * @return bool
	 */
	public static function NativeAvailable() {
		return function_exists('smbclient_state_new');
	}

	/**
	 * @param string $host
	 * @param string $user
	 * @param string $password
	 */
	public function __construct($host, $user, $password) {
		$this->host = $host;
		$this->user = $user;
		$this->password = $password;
	}

	/**
	 * @return string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,11 @@
 	protected $password;
 
 	/**
+	 * @var string $workgroup
+	 */
+	protected $workgroup;
+
+	/**
 	 * Check if the smbclient php extension is available
 	 *
 	 * @return bool
@@ -45,8 +50,26 @@
 	 */
 	public function __construct($host, $user, $password) {
 		$this->host = $host;
+		list($workgroup, $user) = $this->splitUser($user);
 		$this->user = $user;
+		$this->workgroup = $workgroup;
 		$this->password = $password;
+	}
+
+	/**
+	 * Split workgroup from username
+	 *
+	 * @param $user
+	 * @return string[] [$workgroup, $user]
+	 */
+	public function splitUser($user) {
+		if (strpos($user, '/')) {
+			return explode('/', $user, 2);
+		} elseif (strpos($user, '\\')) {
+			return explode('\\', $user);
+		} else {
+			return [null, $user];
+		}
 	}
 
 	/**
@@ -78,13 +101,21 @@
 	}
 
 	/**
+	 * @return string
+	 */
+	public function getWorkgroup() {
+		return $this->workgroup;
+	}
+
+	/**
 	 * @return \Icewind\SMB\IShare[]
 	 *
 	 * @throws \Icewind\SMB\Exception\AuthenticationException
 	 * @throws \Icewind\SMB\Exception\InvalidHostException
 	 */
 	public function listShares() {
-		$command = Server::CLIENT . ' --authentication-file=/proc/self/fd/3' .
+		$workgroupArgument = ($this->workgroup) ? ' -W ' . escapeshellarg($this->workgroup) : '';
+		$command = Server::CLIENT . $workgroupArgument . ' --authentication-file=/proc/self/fd/3' .
 			' -gL ' . escapeshellarg($this->getHost());
 		$connection = new RawConnection($command);
 		$connection->writeAuthentication($this->getUser(), $this->getPassword());
```
