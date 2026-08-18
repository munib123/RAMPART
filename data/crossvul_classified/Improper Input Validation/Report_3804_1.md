# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3804_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3804_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 55-95 of the vulnerable file.

		OC_Filesystem::mount('OC_Filestorage_Local', self::getStorageData(), '/some');
		$this->assertEqual('/', OC_Filesystem::getMountPoint('/'));
		$this->assertEqual('/some/', OC_Filesystem::getMountPoint('/some/folder'));
		$this->assertEqual('/some/', OC_Filesystem::getMountPoint('/some/'));
		$this->assertEqual('/', OC_Filesystem::getMountPoint('/some'));
		$this->assertEqual('folder', OC_Filesystem::getInternalPath('/some/folder'));
	}

	public function testNormalize() {
		$this->assertEqual('/path', OC_Filesystem::normalizePath('/path/'));
		$this->assertEqual('/path/', OC_Filesystem::normalizePath('/path/', false));
		$this->assertEqual('/path', OC_Filesystem::normalizePath('path'));
		$this->assertEqual('/path', OC_Filesystem::normalizePath('\path'));
		$this->assertEqual('/foo/bar', OC_Filesystem::normalizePath('/foo//bar/'));
		$this->assertEqual('/foo/bar', OC_Filesystem::normalizePath('/foo////bar'));
		if (class_exists('Normalizer')) {
			$this->assertEqual("/foo/bar\xC3\xBC", OC_Filesystem::normalizePath("/foo/baru\xCC\x88"));
		}
	}

	public function testHooks() {
		if(OC_Filesystem::getView()){
			$user = OC_User::getUser();
		}else{
			$user=uniqid();
			OC_Filesystem::init('/'.$user.'/files');
		}
		OC_Hook::clear('OC_Filesystem');
		OC_Hook::connect('OC_Filesystem', 'post_write', $this, 'dummyHook');

		OC_Filesystem::mount('OC_Filestorage_Temporary', array(), '/');

		$rootView=new OC_FilesystemView('');
		$rootView->mkdir('/'.$user);
		$rootView->mkdir('/'.$user.'/files');

		OC_Filesystem::file_put_contents('/foo', 'foo');
		OC_Filesystem::mkdir('/bar');
		OC_Filesystem::file_put_contents('/bar//foo', 'foo');

		$tmpFile = OC_Helper::tmpFile();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,6 +72,41 @@
 		}
 	}
 
+	public function testBlacklist() {
+		OC_Hook::clear('OC_Filesystem');
+		OC_Hook::connect('OC_Filesystem', 'write', 'OC_Filesystem', 'isBlacklisted');
+		OC_Hook::connect('OC_Filesystem', 'rename', 'OC_Filesystem', 'isBlacklisted');
+
+		$run = true;
+		OC_Hook::emit(
+			OC_Filesystem::CLASSNAME,
+			OC_Filesystem::signal_write,
+			array(
+				OC_Filesystem::signal_param_path => '/test/.htaccess',
+				OC_Filesystem::signal_param_run => &$run
+			)
+		);
+		$this->assertFalse($run);
+
+		if (OC_Filesystem::getView()) {
+			$user = OC_User::getUser();
+		} else {
+			$user = uniqid();
+			OC_Filesystem::init('/' . $user . '/files');
+		}
+
+		OC_Filesystem::mount('OC_Filestorage_Temporary', array(), '/');
+
+		$rootView = new OC_FilesystemView('');
+		$rootView->mkdir('/' . $user);
+		$rootView->mkdir('/' . $user . '/files');
+
+		$this->assertFalse($rootView->file_put_contents('/.htaccess', 'foo'));
+		$this->assertFalse(OC_Filesystem::file_put_contents('/.htaccess', 'foo'));
+		$fh = fopen(__FILE__, 'r');
+		$this->assertFalse(OC_Filesystem::file_put_contents('/.htaccess', $fh));
+	}
+
 	public function testHooks() {
 		if(OC_Filesystem::getView()){
 			$user = OC_User::getUser();
```
