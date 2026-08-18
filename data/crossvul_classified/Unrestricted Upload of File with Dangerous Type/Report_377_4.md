# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 377_4
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `377_4`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1-36 of the vulnerable file.

<?php

namespace filemanager;

use DB, FileManager, I18n, Restful, Zipper;

/**
 * Provides the JSON API for the admin file manager/browser, as well as functions
 * to verify files and folders.
 */
class API extends Restful {
	/**
	 * Handle list directory requests (/filemanager/api/ls).
	 */
	public function get_ls () {
		$file = urldecode (join ('/', func_get_args ()));

		$res = FileManager::dir ($file);
		if (! $res) {
			return $this->error (FileManager::error ());
		}

		foreach ($res['dirs'] as $k => $dir) {
			$res['dirs'][$k]['mtime'] = I18n::short_date_year_time ($dir['mtime']);
		}

		foreach ($res['files'] as $k => $file) {
			$res['files'][$k]['mtime'] = I18n::short_date_year_time ($file['mtime']);
			$res['files'][$k]['fsize'] = format_filesize ($file['fsize']);
		}

		return $res;
	}

	/**
	 * Handle a directories request (/filemanager/api/dirs).
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,7 +13,7 @@
 	 * Handle list directory requests (/filemanager/api/ls).
 	 */
 	public function get_ls () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 
 		$res = FileManager::dir ($file);
 		if (! $res) {
@@ -43,7 +43,7 @@
 	 * Handle Bitly link requests (/filemanager/api/bitly).
 	 */
 	public function get_bitly () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 		$link = $this->controller->absolutize ('/files/' . $file);
 		return BitlyLink::lookup ($link);
 	}
@@ -52,7 +52,7 @@
 	 * Handle remove file requests (/filemanager/api/rm).
 	 */
 	public function post_rm () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 
 		$res = FileManager::unlink ($file);
 		if (! $res) {
@@ -71,7 +71,7 @@
 	 * Note: Erases the contents of the folder as well.
 	 */
 	public function post_rmdir () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 
 		$res = FileManager::rmdir ($file, true);
 		if (! $res) {
@@ -89,7 +89,7 @@
 	 * Handle rename requests (/filemanager/api/mv).
 	 */
 	public function post_mv () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 
 		$is_folder = FileManager::verify_folder ($file) ? true : false;
 		
@@ -114,7 +114,7 @@
 	 * folders.
 	 */
 	public function post_drop () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 		
 		if (! FileManager::move ($file, $_POST['folder'])) {
 			return $this->error (FileManager::error ());
@@ -133,7 +133,7 @@
 	 * Handle make directory requests (/filemanager/api/mkdir).
 	 */
 	public function post_mkdir () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 		
 		if (! FileManager::mkdir ($file)) {
 			return $this->error (FileManager::error ());
@@ -153,7 +153,7 @@
 	 * be used to set an individual property's value.
 	 */
 	public function post_prop () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 		if (! FileManager::verify_file ($file)) {
 			return $this->error (__ ('Invalid file name'));
 		}
@@ -200,7 +200,7 @@
 	 * Handle unzip requests via (/filemanager/api/unzip).
 	 */
 	public function post_unzip () {
-		$file = urldecode (join ('/', func_get_args ()));
+		$file = trim (urldecode (join ('/', func_get_args ())));
 		if (! FileManager::verify_file ($file)) {
 			return $this->error (__ ('Invalid file name'));
 		}
```
