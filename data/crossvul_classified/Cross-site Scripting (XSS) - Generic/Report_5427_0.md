# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5427_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5427_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 86-109 of the vulnerable file.

	 * @param int $count
	 * @param int $offset
	 * @return JSONResponse
	 */
	public function getEntries($count=50, $offset=0) {
		return new JSONResponse([
			'data' => \OC_Log_Owncloud::getEntries($count, $offset),
			'remain' => count(\OC_Log_Owncloud::getEntries(1, $offset + $count)) !== 0,
		]);
	}

	/**
	 * download logfile
	 *
	 * @NoCSRFRequired
	 *
	 * @return StreamResponse
	 */
	public function download() {
		$resp = new StreamResponse(\OC_Log_Owncloud::getLogFilePath());
		$resp->addHeader('Content-Disposition', 'attachment; filename="owncloud.log"');
		return $resp;
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,6 +103,7 @@
 	 */
 	public function download() {
 		$resp = new StreamResponse(\OC_Log_Owncloud::getLogFilePath());
+		$resp->addHeader('Content-Type', 'application/octet-stream');
 		$resp->addHeader('Content-Disposition', 'attachment; filename="owncloud.log"');
 		return $resp;
 	}
```
