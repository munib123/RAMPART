# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5433_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5433_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 39-79 of the vulnerable file.


	public function isUpdatable($path) {
		return $this->updatables[$path];
	}

	public function isCreatable($path) {
		return $this->updatables[$path];
	}

	public function isDeletable($path) {
		return $this->deletables[$path];
	}

	public function rename($path1, $path2) {
		return $this->canRename;
	}

	public function getRelativePath($path) {
		return $path;
	}
}

/**
 * Class ObjectTree
 *
 * @group DB
 *
 * @package OCA\DAV\Tests\Unit\Connector\Sabre
 */
class ObjectTree extends \Test\TestCase {

	/**
	 * @dataProvider moveFailedProvider
	 * @expectedException \Sabre\DAV\Exception\Forbidden
	 */
	public function testMoveFailed($source, $destination, $updatables, $deletables) {
		$this->moveTest($source, $destination, $updatables, $deletables);
	}

	/**
	 * @dataProvider moveSuccessProvider
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,11 @@
 	public function getRelativePath($path) {
 		return $path;
 	}
+
+	public function getFileInfo($path, $includeMountPoints = true) {
+		$objectTreeTest = new ObjectTreeTest();
+		return $objectTreeTest->getFileInfoMock();
+	}
 }
 
 /**
@@ -66,6 +71,21 @@
  * @package OCA\DAV\Tests\Unit\Connector\Sabre
  */
 class ObjectTree extends \Test\TestCase {
+
+	public function getFileInfoMock() {
+		$mock = $this->getMock('\OCP\Files\FileInfo');
+		$mock
+			->expects($this->any())
+			->method('isDeletable')
+			->willReturn(true);
+		$mock
+			->expects($this->any())
+			->method('isUpdateable')
+			->willReturn(true);
+
+		return $mock;
+	}
+
 
 	/**
 	 * @dataProvider moveFailedProvider
```
