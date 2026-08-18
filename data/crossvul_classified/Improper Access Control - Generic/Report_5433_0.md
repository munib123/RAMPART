# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5433_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5433_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 54-94 of the vulnerable file.

	public function __construct() {
	}

	/**
	 * @param \Sabre\DAV\INode $rootNode
	 * @param \OC\Files\View $view
	 * @param  \OCP\Files\Mount\IMountManager $mountManager
	 */
	public function init(\Sabre\DAV\INode $rootNode, \OC\Files\View $view, \OCP\Files\Mount\IMountManager $mountManager) {
		$this->rootNode = $rootNode;
		$this->fileView = $view;
		$this->mountManager = $mountManager;
	}

	/**
	 * If the given path is a chunked file name, converts it
	 * to the real file name. Only applies if the OC-CHUNKED header
	 * is present.
	 *
	 * @param string $path chunk file path to convert
	 * 
	 * @return string path to real file
	 */
	private function resolveChunkFile($path) {
		if (isset($_SERVER['HTTP_OC_CHUNKED'])) {
			// resolve to real file name to find the proper node
			list($dir, $name) = \Sabre\HTTP\URLUtil::splitPath($path);
			if ($dir == '/' || $dir == '.') {
				$dir = '';
			}

			$info = \OC_FileChunking::decodeName($name);
			// only replace path if it was really the chunked file
			if (isset($info['transferid'])) {
				// getNodePath is called for multiple nodes within a chunk
				// upload call
				$path = $dir . '/' . $info['name'];
				$path = ltrim($path, '/');
			}
		}
		return $path;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,7 +71,7 @@
 	 * is present.
 	 *
 	 * @param string $path chunk file path to convert
-	 * 
+	 *
 	 * @return string path to real file
 	 */
 	private function resolveChunkFile($path) {
@@ -184,14 +184,27 @@
 	 *
 	 * @param string $sourcePath The path to the file which should be moved
 	 * @param string $destinationPath The full destination path, so not just the destination parent node
-	 * @throws \Sabre\DAV\Exception\BadRequest
+	 * @return int
+	 * @throws FileLocked
+	 * @throws Forbidden
+	 * @throws InvalidPath
+	 * @throws \Sabre\DAV\Exception\Forbidden
+	 * @throws \Sabre\DAV\Exception\Locked
+	 * @throws \Sabre\DAV\Exception\NotFound
 	 * @throws \Sabre\DAV\Exception\ServiceUnavailable
-	 * @throws \Sabre\DAV\Exception\Forbidden
-	 * @return int
 	 */
 	public function move($sourcePath, $destinationPath) {
 		if (!$this->fileView) {
 			throw new \Sabre\DAV\Exception\ServiceUnavailable('filesystem not setup');
+		}
+
+		$infoDestination = $this->fileView->getFileInfo(dirname($destinationPath));
+		$infoSource = $this->fileView->getFileInfo($sourcePath);
+		$destinationPermission = $infoDestination && $infoDestination->isUpdateable();
+		$sourcePermission =  $infoSource && $infoSource->isDeletable();
+
+		if (!$destinationPermission || !$sourcePermission) {
+			throw new Forbidden('No permissions to move object.');
 		}
 
 		$targetNodeExists = $this->nodeExists($destinationPath);
@@ -263,14 +276,24 @@
 	 *
 	 * @param string $source
 	 * @param string $destination
+	 * @throws FileLocked
+	 * @throws Forbidden
+	 * @throws InvalidPath
+	 * @throws \Exception
+	 * @throws \Sabre\DAV\Exception\Locked
+	 * @throws \Sabre\DAV\Exception\NotFound
 	 * @throws \Sabre\DAV\Exception\ServiceUnavailable
-	 * @return void
 	 */
 	public function copy($source, $destination) {
 		if (!$this->fileView) {
 			throw new \Sabre\DAV\Exception\ServiceUnavailable('filesystem not setup');
 		}
 
+		$info = $this->fileView->getFileInfo(dirname($destination));
+		if ($info && !$info->isUpdateable()) {
+			throw new Forbidden('No permissions to copy object.');
+		}
+		
 		// this will trigger existence check
 		$this->getNodeForPath($source);
 
```
