# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5439_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5439_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 563-603 of the vulnerable file.

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

	private function doTestRestore() {
		$filePath = self::TEST_VERSIONS_USER . '/files/sub/test.txt';
		$this->rootView->file_put_contents($filePath, 'test file');

		$t0 = $this->rootView->filemtime($filePath);

		// not exactly the same timestamp as the file
		$t1 = time() - 60;
		// second version is two weeks older
		$t2 = $t1 - 60 * 60 * 24 * 14;

		// create some versions
		$v1 = self::USERS_VERSIONS_ROOT . '/sub/test.txt.v' . $t1;
		$v2 = self::USERS_VERSIONS_ROOT . '/sub/test.txt.v' . $t2;

		$this->rootView->mkdir(self::USERS_VERSIONS_ROOT . '/sub');
		$this->rootView->file_put_contents($v1, 'version1');
		$this->rootView->file_put_contents($v2, 'version2');

		$oldVersions = \OCA\Files_Versions\Storage::getVersions(
			self::TEST_VERSIONS_USER, '/sub/test.txt'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -580,6 +580,68 @@
 		$this->doTestRestore();
 	}
 
+	public function testRestoreNoPermission() {
+		$this->loginAsUser(self::TEST_VERSIONS_USER);
+
+		$userHome = \OC::$server->getUserFolder(self::TEST_VERSIONS_USER);
+		$node = $userHome->newFolder('folder');
+		$file = $node->newFile('test.txt');
+
+		\OCP\Share::shareItem(
+			'folder',
+			$file->getId(),
+			\OCP\Share::SHARE_TYPE_USER,
+			self::TEST_VERSIONS_USER2,
+			\OCP\Constants::PERMISSION_READ
+		);
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
+		$this->assertEquals('test file', $file->getContent(), 'File content has not changed');
+	}
+
+	/**
+	 * @param string $hookName name of hook called
+	 * @param string $params variable to recieve parameters provided by hook
+	 */
+	private function connectMockHooks($hookName, &$params) {
+		if ($hookName === null) {
+			return;
+		}
+
+		$eventHandler = $this->getMockBuilder('\stdclass')
+			->setMethods(['callback'])
+			->getMock();
+
+		$eventHandler->expects($this->any())
+			->method('callback')
+			->will($this->returnCallback(
+				function($p) use (&$params) {
+					$params = $p;
+				}
+			));
+
+		\OCP\Util::connectHook(
+			'\OCP\Versions',
+			$hookName,
+			$eventHandler,
+			'callback'
+		);
+	}
+
 	private function doTestRestore() {
 		$filePath = self::TEST_VERSIONS_USER . '/files/sub/test.txt';
 		$this->rootView->file_put_contents($filePath, 'test file');
@@ -739,6 +801,8 @@
 		// note: we cannot predict how many versions are created due to
 		// test run timing
 		$this->assertGreaterThan(0, count($versions));
+
+		return $versions;
 	}
 
 	/**
```
