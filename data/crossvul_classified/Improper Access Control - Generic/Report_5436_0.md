# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5436_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5436_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 189-229 of the vulnerable file.


	/**
	 * Copies a file or directory.
	 *
	 * This method must work recursively and delete the destination
	 * if it exists
	 *
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

		try {
			if ($this->fileView->is_file($source)) {
				$this->fileView->copy($source, $destination);
			} else {
				$this->fileView->mkdir($destination);
				$dh = $this->fileView->opendir($source);
				if (is_resource($dh)) {
					while (($subNode = readdir($dh)) !== false) {

						if ($subNode == '.' || $subNode == '..') continue;
						$this->copy($source . '/' . $subNode, $destination . '/' . $subNode);

					}
				}
			}
		} catch (\OCP\Files\StorageNotAvailableException $e) {
			throw new \Sabre\DAV\Exception\ServiceUnavailable($e->getMessage());
		}

		list($destinationDir,) = \Sabre\DAV\URLUtil::splitPath($destination);
		$this->markDirty($destinationDir);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,6 +206,14 @@
 		// this will trigger existence check
 		$this->getNodeForPath($source);
 
+		$destinationDir = dirname($destination);
+		if ($destinationDir === '.') {
+			$destinationDir = '';
+		}
+		if (!$this->fileView->isCreatable($destinationDir)) {
+			throw new \Sabre\DAV\Exception\Forbidden();
+		}
+
 		try {
 			if ($this->fileView->is_file($source)) {
 				$this->fileView->copy($source, $destination);
```
