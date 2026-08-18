# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5439_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5439_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 270-310 of the vulnerable file.


		// if we moved versions directly for a file, schedule expiration check for that file
		if (!$rootView->is_dir('/' . $targetOwner . '/files/' . $targetPath)) {
			self::scheduleExpire($targetOwner, $targetPath);
		}

	}

	/**
	 * Rollback to an old version of a file.
	 *
	 * @param string $file file name
	 * @param int $revision revision timestamp
	 */
	public static function rollback($file, $revision) {

		if(\OCP\Config::getSystemValue('files_versions', Storage::DEFAULTENABLED)=='true') {
			// add expected leading slash
			$file = '/' . ltrim($file, '/');
			list($uid, $filename) = self::getUidAndFilename($file);
			$users_view = new \OC\Files\View('/'.$uid);
			$files_view = new \OC\Files\View('/'.\OCP\User::getUser().'/files');
			$versionCreated = false;

			//first create a new version
			$version = 'files_versions'.$filename.'.v'.$users_view->filemtime('files'.$filename);
			if ( !$users_view->file_exists($version)) {

				$users_view->copy('files'.$filename, 'files_versions'.$filename.'.v'.$users_view->filemtime('files'.$filename));

				$versionCreated = true;
			}

			$fileToRestore =  'files_versions' . $filename . '.v' . $revision;

			$oldFileInfo = $users_view->getFileInfo($fileToRestore);
			$newFileInfo = $files_view->getFileInfo($filename);
			$cache = $newFileInfo->getStorage()->getCache();
			$cache->update(
				$newFileInfo->getId(), [
					'size' => $oldFileInfo->getSize()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -287,8 +287,16 @@
 			// add expected leading slash
 			$file = '/' . ltrim($file, '/');
 			list($uid, $filename) = self::getUidAndFilename($file);
+			if ($uid === null || trim($filename, '/') === '') {
+				return false;
+			}
 			$users_view = new \OC\Files\View('/'.$uid);
 			$files_view = new \OC\Files\View('/'.\OCP\User::getUser().'/files');
+
+			if (!$files_view->isUpdatable($filename)) {
+				return false;
+			}
+
 			$versionCreated = false;
 
 			//first create a new version
```
