# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5438_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5438_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 61-101 of the vulnerable file.


	// files for which we can remove the versions after the delete operation was successful
	private static $deletedFiles = array();

	private static $sourcePathAndUser = array();

	private static $max_versions_per_interval = array(
		//first 10sec, one version every 2sec
		1 => array('intervalEndsAfter' => 10,      'step' => 2),
		//next minute, one version every 10sec
		2 => array('intervalEndsAfter' => 60,      'step' => 10),
		//next hour, one version every minute
		3 => array('intervalEndsAfter' => 3600,    'step' => 60),
		//next 24h, one version every hour
		4 => array('intervalEndsAfter' => 86400,   'step' => 3600),
		//next 30days, one version per day
		5 => array('intervalEndsAfter' => 2592000, 'step' => 86400),
		//until the end one version per week
		6 => array('intervalEndsAfter' => -1,      'step' => 604800),
	);
	
	/** @var \OCA\Files_Versions\AppInfo\Application */
	private static $application;

	/**
	 * get the UID of the owner of the file and the path to the file relative to
	 * owners files folder
	 *
	 * @param string $filename
	 * @return array
	 * @throws \OC\User\NoUserException
	 */
	public static function getUidAndFilename($filename) {
		$uid = Filesystem::getOwner($filename);
		$userManager = \OC::$server->getUserManager();
		// if the user with the UID doesn't exists, e.g. because the UID points
		// to a remote user with a federated cloud ID we use the current logged-in
		// user. We need a valid local user to create the versions
		if (!$userManager->userExists($uid)) {
			$uid = User::getUser();
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,7 @@
 		//until the end one version per week
 		6 => array('intervalEndsAfter' => -1,      'step' => 604800),
 	);
-	
+
 	/** @var \OCA\Files_Versions\AppInfo\Application */
 	private static $application;
 
@@ -325,6 +325,13 @@
 			$files_view = new View('/'. User::getUser().'/files');
 			$versionCreated = false;
 
+			$fileInfo = $files_view->getFileInfo($file);
+
+			// check if user has the permissions to revert a version
+			if (!$fileInfo->isUpdateable()) {
+				return false;
+			}
+
 			//first create a new version
 			$version = 'files_versions'.$filename.'.v'.$users_view->filemtime('files'.$filename);
 			if (!$users_view->file_exists($version)) {
@@ -338,10 +345,9 @@
 			// This has to happen manually here since the file is manually copied below
 			$oldVersion = $users_view->getFileInfo($fileToRestore)->getEncryptedVersion();
 			$oldFileInfo = $users_view->getFileInfo($fileToRestore);
-			$newFileInfo = $files_view->getFileInfo($filename);
-			$cache = $newFileInfo->getStorage()->getCache();
+			$cache = $fileInfo->getStorage()->getCache();
 			$cache->update(
-				$newFileInfo->getId(), [
+				$fileInfo->getId(), [
 					'encrypted' => $oldVersion,
 					'encryptedVersion' => $oldVersion,
 					'size' => $oldFileInfo->getSize()
@@ -681,7 +687,7 @@
 	public static function expire($filename) {
 		$config = \OC::$server->getConfig();
 		$expiration = self::getExpiration();
-		
+
 		if($config->getSystemValue('files_versions', Storage::DEFAULTENABLED)=='true' && $expiration->isEnabled()) {
 
 			if (!Filesystem::file_exists($filename)) {
```
