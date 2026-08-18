# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3553_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3553_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 361-401 of the vulnerable file.

				));
			}
			
			if(!$record->canEdit()) {
				$form->makeReadonly();
			}

			$this->extend('updateEditForm', $form);

			return $form;
		}
	}
	
	/**
	 * Perform the "move marked" action.
	 * Called and returns in same way as 'save' function
	 */
	public function movemarked($urlParams, $form) {
		if($_REQUEST['DestFolderID'] && (is_numeric($_REQUEST['DestFolderID']) || ($_REQUEST['DestFolderID']) == 'root')) {
			$destFolderID = ($_REQUEST['DestFolderID'] == 'root') ? 0 : $_REQUEST['DestFolderID'];
			$fileList = "'" . ereg_replace(' *, *',"','",trim(addslashes($_REQUEST['FileIDs']))) . "'";
			$numFiles = 0;
	
			if($fileList != "''") {
				$files = DataObject::get("File", "\"File\".\"ID\" IN ($fileList)");
				if($files) {
					foreach($files as $file) {
						if($file instanceof Image) {
							$file->deleteFormattedImages();
						}
						$file->ParentID = $destFolderID;
						$file->write();
						$numFiles++;
					}
				} else {
					user_error("No files in $fileList could be found!", E_USER_ERROR);
				}
			}

			$message = sprintf(_t('AssetAdmin.MOVEDX','Moved %s files'),$numFiles);
			
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -378,7 +378,7 @@
 	public function movemarked($urlParams, $form) {
 		if($_REQUEST['DestFolderID'] && (is_numeric($_REQUEST['DestFolderID']) || ($_REQUEST['DestFolderID']) == 'root')) {
 			$destFolderID = ($_REQUEST['DestFolderID'] == 'root') ? 0 : $_REQUEST['DestFolderID'];
-			$fileList = "'" . ereg_replace(' *, *',"','",trim(addslashes($_REQUEST['FileIDs']))) . "'";
+			$fileList = "'" . ereg_replace(' *, *',"','",trim(Convert::raw2sql($_REQUEST['FileIDs']))) . "'";
 			$numFiles = 0;
 	
 			if($fileList != "''") {
@@ -411,7 +411,7 @@
 	 * Called and returns in same way as 'save' function
 	 */
 	public function deletemarked($urlParams, $form) {
-		$fileList = "'" . ereg_replace(' *, *',"','",trim(addslashes($_REQUEST['FileIDs']))) . "'";
+		$fileList = "'" . ereg_replace(' *, *',"','",trim(Convert::raw2sql($_REQUEST['FileIDs']))) . "'";
 		$numFiles = 0;
 		$folderID = 0;
 		$deleteList = '';
```
