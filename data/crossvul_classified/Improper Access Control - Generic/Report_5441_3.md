# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5441_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5441_3`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 586-626 of the vulnerable file.

	public function testExpireNonexistingFile() {
		$this->logout();
		// needed to have a FS setup (the background job does this)
		\OC_Util::setupFS(self::TEST_VERSIONS_USER);

		$this->assertFalse(\OCA\Files_Versions\Storage::expire('/void/unexist.txt'));
	}

	public function testRestoreSameStorage() {
		\OC\Files\Filesystem::mkdir('sub');
		$this->doTestRestore();
	}

	public function testRestoreCrossStorage() {
		$storage2 = new Temporary(array());
		\OC\Files\Filesystem::mount($storage2, array(), self::TEST_VERSIONS_USER . '/files/sub');

		$this->doTestRestore();
	}

	/**
	 * @param string $hookName name of hook called
	 * @param string $params variable to recieve parameters provided by hook
	 */
	private function connectMockHooks($hookName, &$params) {
		if ($hookName === null) {
			return;
		}

		$eventHandler = $this->getMockBuilder('\stdclass')
			->setMethods(['callback'])
			->getMock();

		$eventHandler->expects($this->any())
			->method('callback')
			->will($this->returnCallback(
				function($p) use (&$params) {
					$params = $p;
				}
			));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -603,6 +603,40 @@
 		$this->doTestRestore();
 	}
 
+	public function testRestoreNoPermission() {
+		$this->loginAsUser(self::TEST_VERSIONS_USER);
+
+		$userHome = \OC::$server->getUserFolder(self::TEST_VERSIONS_USER);
+		$node = $userHome->newFolder('folder');
+		$file = $node->newFile('test.txt');
+
+		$share = \OC::$server->getShareManager()->newShare();
+		$share->setNode($node)
+			->setShareType(\OCP\Share::SHARE_TYPE_USER)
+			->setSharedBy(self::TEST_VERSIONS_USER)
+			->setSharedWith(self::TEST_VERSIONS_USER2)
+			->setPermissions(\OCP\Constants::PERMISSION_READ);
+		$share = \OC::$server->getShareManager()->createShare($share);
+
+		$versions = $this->createAndCheckVersions(
+			\OC\Files\Filesystem::getView(),
+			'folder/test.txt'
+		);
+
+		$file->putContent('test file');
+
+		$this->loginAsUser(self::TEST_VERSIONS_USER2);
+
+		$firstVersion = current($versions);
+
+		$this->assertFalse(\OCA\Files_Versions\Storage::rollback('folder/test.txt', $firstVersion['version']), 'Revert did not happen');
+
+		$this->loginAsUser(self::TEST_VERSIONS_USER);
+
+		\OC::$server->getShareManager()->deleteShare($share);
+		$this->assertEquals('test file', $file->getContent(), 'File content has not changed');
+	}
+
 	/**
 	 * @param string $hookName name of hook called
 	 * @param string $params variable to recieve parameters provided by hook
@@ -663,7 +697,7 @@
 		$params = array();
 		$this->connectMockHooks('rollback', $params);
 
-		\OCA\Files_Versions\Storage::rollback('sub/test.txt', $t2);
+		$this->assertTrue(\OCA\Files_Versions\Storage::rollback('sub/test.txt', $t2));
 		$expectedParams = array(
 			'path' => '/sub/test.txt',
 		);
@@ -805,6 +839,8 @@
 		// note: we cannot predict how many versions are created due to
 		// test run timing
 		$this->assertGreaterThan(0, count($versions));
+
+		return $versions;
 	}
 
 	/**
```
