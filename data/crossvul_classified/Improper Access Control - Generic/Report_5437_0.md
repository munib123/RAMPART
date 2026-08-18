# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5437_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5437_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 253-284 of the vulnerable file.

	 * @param string $source
	 * @param string $destination
	 * @throws \Sabre\DAV\Exception\ServiceUnavailable
	 * @return void
	 */
	public function copy($source, $destination) {
		if (!$this->fileView) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable('filesystem not setup');
		}

		// this will trigger existence check
		$this->getNodeForPath($source);

		list($destinationDir, $destinationName) = \Sabre\HTTP\URLUtil::splitPath($destination);
		try {
			$this->fileView->verifyPath($destinationDir, $destinationName);
		} catch (\OCP\Files\InvalidPathException $ex) {
			throw new InvalidPath($ex->getMessage());
		}

		try {
			$this->fileView->copy($source, $destination);
		} catch (StorageNotAvailableException $e) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable($e->getMessage());
		} catch (LockedException $e) {
			throw new FileLocked($e->getMessage(), $e->getCode(), $e);
		}

		list($destinationDir,) = \Sabre\HTTP\URLUtil::splitPath($destination);
		$this->markDirty($destinationDir);
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -270,6 +270,11 @@
 			throw new InvalidPath($ex->getMessage());
 		}
 
+		// Webdav's copy will implicitly do a delete+create, so only create+delete permissions are required
+		if (!$this->fileView->isCreatable($destinationDir)) {
+			throw new \Sabre\DAV\Exception\Forbidden();
+		}
+
 		try {
 			$this->fileView->copy($source, $destination);
 		} catch (StorageNotAvailableException $e) {
```
