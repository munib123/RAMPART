# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5442_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5442_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 518-558 of the vulnerable file.

			$this->assertSame('/subfolder/test.txt', $version['path']);
			$this->assertSame('test.txt', $version['name']);
		}

		//cleanup
		$this->rootView->deleteAll(self::USERS_VERSIONS_ROOT . '/subfolder');
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
@@ -535,6 +535,68 @@
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
@@ -615,6 +677,87 @@
 			isset($newVersions[$t2 . '#' . 'test.txt']),
 			'Restored version is not in the list any more'
 		);
+	}
+
+	/**
+	 * Test whether versions are created when overwriting as owner
+	 */
+	public function testStoreVersionAsOwner() {
+		$this->loginAsUser(self::TEST_VERSIONS_USER);
+
+		$this->createAndCheckVersions(
+			\OC\Files\Filesystem::getView(),
+			'test.txt'
+		);
+	}
+
+	/**
+	 * Test whether versions are created when overwriting as share recipient
+	 */
+	public function testStoreVersionAsRecipient() {
+		$this->loginAsUser(self::TEST_VERSIONS_USER);
+
+		\OC\Files\Filesystem::mkdir('folder');
+		\OC\Files\Filesystem::file_put_contents('folder/test.txt', 'test file');
+		$fileInfo = \OC\Files\Filesystem::getFileInfo('folder');
+
+		\OCP\Share::shareItem(
+			'folder',
+			$fileInfo['fileid'],
+			\OCP\Share::SHARE_TYPE_USER,
+			self::TEST_VERSIONS_USER2,
+			\OCP\Constants::PERMISSION_ALL
+		);
+
+		$this->loginAsUser(self::TEST_VERSIONS_USER2);
+
+		$this->createAndCheckVersions(
+			\OC\Files\Filesystem::getView(),
+			'folder/test.txt'
+		);
+	}
+
+	/**
+	 * Test whether versions are created when overwriting anonymously.
+	 *
+	 * When uploading through a public link or publicwebdav, no user
+	 * is logged in. File modification must still be able to find
+	 * the owner and create versions.
+	 */
+	public function testStoreVersionAsAnonymous() {
+		$this->logout();
+
+		// note: public link upload does this,
+		// needed to make the hooks fire
+		\OC_Util::setupFS(self::TEST_VERSIONS_USER);
+
+		$userView = new \OC\Files\View('/' . self::TEST_VERSIONS_USER . '/files');
+		$this->createAndCheckVersions(
+			$userView,
+			'test.txt'
+		);
+	}
+
+	private function createAndCheckVersions($view, $path) {
+		$view->file_put_contents($path, 'test file');
+		$view->file_put_contents($path, 'version 1');
+		$view->file_put_contents($path, 'version 2');
+
+		$this->loginAsUser(self::TEST_VERSIONS_USER);
+
+		// need to scan for the versions
+		list($rootStorage,) = $this->rootView->resolvePath(self::TEST_VERSIONS_USER . '/files_versions');
+		$rootStorage->getScanner()->scan('files_versions');
+
+		$versions = \OCA\Files_Versions\Storage::getVersions(
+			self::TEST_VERSIONS_USER, '/' . $path
+		);
+
+		// note: we cannot predict how many versions are created due to
+		// test run timing
+		$this->assertGreaterThan(0, count($versions));
+
+		return $versions;
 	}
 
 	/**
```
