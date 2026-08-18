# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5437_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5437_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 100-140 of the vulnerable file.

	 */
	private function moveTest($source, $destination, $updatables, $deletables) {
		$view = new TestDoubleFileView($updatables, $deletables);

		$info = new FileInfo('', null, null, array(), null);

		$rootDir = new Directory($view, $info);
		$objectTree = $this->getMock('\OC\Connector\Sabre\ObjectTree',
			array('nodeExists', 'getNodeForPath'),
			array($rootDir, $view));

		$objectTree->expects($this->once())
			->method('getNodeForPath')
			->with($this->identicalTo($source))
			->will($this->returnValue(false));

		/** @var $objectTree \OC\Connector\Sabre\ObjectTree */
		$mountManager = \OC\Files\Filesystem::getMountManager();
		$objectTree->init($rootDir, $view, $mountManager);
		$objectTree->move($source, $destination);
	}

	/**
	 * @dataProvider nodeForPathProvider
	 */
	public function testGetNodeForPath(
		$inputFileName,
		$fileInfoQueryPath,
		$outputFileName,
		$type,
		$enableChunkingHeader
	) {

		if ($enableChunkingHeader) {
			$_SERVER['HTTP_OC_CHUNKED'] = true;
		}

		$rootNode = $this->getMockBuilder('\OC\Connector\Sabre\Directory')
			->disableOriginalConstructor()
			->getMock();
		$mountManager = $this->getMock('\OC\Files\Mount\Manager');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,6 +117,88 @@
 		$mountManager = \OC\Files\Filesystem::getMountManager();
 		$objectTree->init($rootDir, $view, $mountManager);
 		$objectTree->move($source, $destination);
+	}
+
+	public function copyDataProvider() {
+		return [
+			// copy into same dir
+			['a', 'b', ''],
+			// copy into same dir
+			['a/a', 'a/b', 'a'],
+			// copy into another dir
+			['a', 'sub/a', 'sub'],
+		];
+	}
+
+	/**
+	 * @dataProvider copyDataProvider
+	 */
+	public function testCopy($sourcePath, $targetPath, $targetParent) {
+		$view = $this->getMock('\OC\Files\View');
+		$view->expects($this->once())
+			->method('verifyPath')
+			->with($targetParent)
+			->will($this->returnValue(true));
+		$view->expects($this->once())
+			->method('isCreatable')
+			->with($targetParent)
+			->will($this->returnValue(true));
+		$view->expects($this->once())
+			->method('copy')
+			->with($sourcePath, $targetPath)
+			->will($this->returnValue(true));
+
+		$info = new FileInfo('', null, null, array(), null);
+
+		$rootDir = new \OC\Connector\Sabre\Directory($view, $info);
+		$objectTree = $this->getMock('\OC\Connector\Sabre\ObjectTree',
+			array('nodeExists', 'getNodeForPath'),
+			array($rootDir, $view));
+
+		$objectTree->expects($this->once())
+			->method('getNodeForPath')
+			->with($this->identicalTo($sourcePath))
+			->will($this->returnValue(false));
+
+		/** @var $objectTree \OC\Connector\Sabre\ObjectTree */
+		$mountManager = \OC\Files\Filesystem::getMountManager();
+		$objectTree->init($rootDir, $view, $mountManager);
+		$objectTree->copy($sourcePath, $targetPath);
+	}
+
+	/**
+	 * @dataProvider copyDataProvider
+	 * @expectedException \Sabre\DAV\Exception\Forbidden
+	 */
+	public function testCopyFailNotCreatable($sourcePath, $targetPath, $targetParent) {
+		$view = $this->getMock('\OC\Files\View');
+		$view->expects($this->once())
+			->method('verifyPath')
+			->with($targetParent)
+			->will($this->returnValue(true));
+		$view->expects($this->once())
+			->method('isCreatable')
+			->with($targetParent)
+			->will($this->returnValue(false));
+		$view->expects($this->never())
+			->method('copy');
+
+		$info = new FileInfo('', null, null, array(), null);
+
+		$rootDir = new \OC\Connector\Sabre\Directory($view, $info);
+		$objectTree = $this->getMock('\OC\Connector\Sabre\ObjectTree',
+			array('nodeExists', 'getNodeForPath'),
+			array($rootDir, $view));
+
+		$objectTree->expects($this->once())
+			->method('getNodeForPath')
+			->with($this->identicalTo($sourcePath))
+			->will($this->returnValue(false));
+
+		/** @var $objectTree \OC\Connector\Sabre\ObjectTree */
+		$mountManager = \OC\Files\Filesystem::getMountManager();
+		$objectTree->init($rootDir, $view, $mountManager);
+		$objectTree->copy($sourcePath, $targetPath);
 	}
 
 	/**
```
