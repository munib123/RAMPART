# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 1758_3
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1758_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 40-80 of the vulnerable file.


	/**
	 * @param Server $server
	 * @param string $name
	 */
	public function __construct($server, $name) {
		$this->server = $server;
		$this->name = $name;
		$this->parser = new Parser(new TimeZoneProvider($this->server->getHost()));
	}

	/**
	 * @throws \Icewind\SMB\Exception\ConnectionException
	 * @throws \Icewind\SMB\Exception\AuthenticationException
	 * @throws \Icewind\SMB\Exception\InvalidHostException
	 */
	protected function connect() {
		if ($this->connection and $this->connection->isValid()) {
			return;
		}
		$command = sprintf('%s --authentication-file=/proc/self/fd/3 //%s/%s',
			Server::CLIENT,
			$this->server->getHost(),
			$this->name
		);
		$this->connection = new Connection($command);
		$this->connection->writeAuthentication($this->server->getUser(), $this->server->getPassword());
		if (!$this->connection->isValid()) {
			throw new ConnectionException();
		}
	}

	protected function reconnect() {
		$this->connection->reconnect();
		$this->connection->writeAuthentication($this->server->getUser(), $this->server->getPassword());
		if (!$this->connection->isValid()) {
			throw new ConnectionException();
		}
	}

	/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,8 +57,10 @@
 		if ($this->connection and $this->connection->isValid()) {
 			return;
 		}
-		$command = sprintf('%s --authentication-file=/proc/self/fd/3 //%s/%s',
+		$workgroupArgument = ($this->server->getWorkgroup()) ? ' -W ' . escapeshellarg($this->server->getWorkgroup()) : '';
+		$command = sprintf('%s %s --authentication-file=/proc/self/fd/3 //%s/%s',
 			Server::CLIENT,
+			$workgroupArgument,
 			$this->server->getHost(),
 			$this->name
 		);
@@ -260,8 +262,10 @@
 		$source = str_replace('\'', '\'"\'"\'', $source);
 		// since returned stream is closed by the caller we need to create a new instance
 		// since we can't re-use the same file descriptor over multiple calls
-		$command = sprintf('%s --authentication-file=/proc/self/fd/3 //%s/%s -c \'get %s /proc/self/fd/5\'',
+		$workgroupArgument = ($this->server->getWorkgroup()) ? ' -W ' . escapeshellarg($this->server->getWorkgroup()) : '';
+		$command = sprintf('%s %s --authentication-file=/proc/self/fd/3 //%s/%s -c \'get %s /proc/self/fd/5\'',
 			Server::CLIENT,
+			$workgroupArgument,
 			$this->server->getHost(),
 			$this->name,
 			$source
@@ -288,8 +292,10 @@
 		$target = str_replace('\'', '\'"\'"\'', $target);
 		// since returned stream is closed by the caller we need to create a new instance
 		// since we can't re-use the same file descriptor over multiple calls
-		$command = sprintf('%s --authentication-file=/proc/self/fd/3 //%s/%s -c \'put /proc/self/fd/4 %s\'',
+		$workgroupArgument = ($this->server->getWorkgroup()) ? ' -W ' . escapeshellarg($this->server->getWorkgroup()) : '';
+		$command = sprintf('%s %s --authentication-file=/proc/self/fd/3 //%s/%s -c \'put /proc/self/fd/4 %s\'',
 			Server::CLIENT,
+			$workgroupArgument,
 			$this->server->getHost(),
 			$this->name,
 			$target
```
