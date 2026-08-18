# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3802_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3802_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 351-391 of the vulnerable file.

		$newpath = $path;
		if (strncmp($newpath, $datadir, strlen($datadir)) == 0) {
			$newpath = substr($path, strlen($datadir));
		}
		return $newpath;
	}
	
	/**
	 * check if the requested path is valid
	 * @param string path
	 * @return bool
	 */
	static public function isValidPath($path){
		$path = str_replace('\\', '/', $path);
		if(!$path || $path[0]!=='/'){
			$path='/'.$path;
		}
		if(strstr($path,'/../') || strrchr($path, '/') === '/..' ){
			return false;
		}
		return true;
	}
	
	/**
	 * checks if a file is blacklisted for storage in the filesystem
	 * Listens to write and rename hooks
	 * @param array $data from hook
	 */
	static public function isBlacklisted($data){
		$blacklist = array('.htaccess');
		if (isset($data['path'])) {
			$path = $data['path'];
		} else if (isset($data['newpath'])) {
			$path = $data['newpath'];
		}
		if (isset($path)) {
			$filename = strtolower(basename($path));
			if (in_array($filename, $blacklist)) {
				$data['run'] = false;
			}
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -368,6 +368,9 @@
 		if(strstr($path,'/../') || strrchr($path, '/') === '/..' ){
 			return false;
 		}
+		if(self::isFileBlacklisted($path)){
+			return false;
+		}
 		return true;
 	}
 	
@@ -376,21 +379,23 @@
 	 * Listens to write and rename hooks
 	 * @param array $data from hook
 	 */
-	static public function isBlacklisted($data){
-		$blacklist = array('.htaccess');
+	static public function isBlacklisted($data) {
 		if (isset($data['path'])) {
 			$path = $data['path'];
 		} else if (isset($data['newpath'])) {
 			$path = $data['newpath'];
 		}
 		if (isset($path)) {
-			$filename = strtolower(basename($path));
-			if (in_array($filename, $blacklist)) {
-				$data['run'] = false;
-			}
-		}
-	}
-	
+			$data['run'] = !self::isFileBlacklisted($path);
+		}
+	}
+
+	static public function isFileBlacklisted($path){
+		$blacklist = array('.htaccess');
+		$filename = strtolower(basename($path));
+		return in_array($filename, $blacklist);
+	}
+
 	/**
 	 * following functions are equivalent to their php builtin equivalents for arguments/return values.
 	 */
```
