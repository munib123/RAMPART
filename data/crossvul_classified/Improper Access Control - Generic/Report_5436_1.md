# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5436_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5436_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
/**
 * Copyright (c) 2013 Thomas Müller <thomas.mueller@tmit.eu>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */

namespace Test\OC\Connector\Sabre;


use OC\Files\FileInfo;
use OC_Connector_Sabre_Directory;
use PHPUnit_Framework_TestCase;

class TestDoubleFileView extends \OC\Files\View {

	public function __construct($updatables, $deletables, $canRename = true) {
		$this->updatables = $updatables;
		$this->deletables = $deletables;
		$this->canRename = $canRename;
	}

	public function isUpdatable($path) {
		return $this->updatables[$path];
	}

	public function isCreatable($path) {
		return $this->updatables[$path];
	}

	public function isDeletable($path) {
		return $this->deletables[$path];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,7 +10,7 @@
 
 
 use OC\Files\FileInfo;
-use OC_Connector_Sabre_Directory;
+use OC\Files\Storage\Temporary;
 use PHPUnit_Framework_TestCase;
 
 class TestDoubleFileView extends \OC\Files\View {
@@ -103,7 +103,7 @@
 
 		$info = new FileInfo('', null, null, array(), null);
 
-		$rootDir = new OC_Connector_Sabre_Directory($view, $info);
+		$rootDir = new \OC_Connector_Sabre_Directory($view, $info);
 		$objectTree = $this->getMock('\OC\Connector\Sabre\ObjectTree',
 			array('nodeExists', 'getNodeForPath'),
 			array($rootDir, $view));
@@ -119,4 +119,85 @@
 		$objectTree->move($source, $dest);
 	}
 
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
+			->method('is_file')
+			->with($sourcePath)
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
+		$rootDir = new \OC_Connector_Sabre_Directory($view, $info);
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
+		$view->expects($this->any())
+			->method('is_file')
+			->with($sourcePath)
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
+		$rootDir = new \OC_Connector_Sabre_Directory($view, $info);
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
 }
```
