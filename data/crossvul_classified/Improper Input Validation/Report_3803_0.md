# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 3803_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3803_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 344-384 of the vulnerable file.

	/**
	* return path to file which reflects one visible in browser
	* @param string path
	* @return string
	*/
	static public function getLocalPath($path) {
		$datadir = \OCP\Config::getSystemValue('datadirectory').'/'.\OC_User::getUser().'/files';
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -361,6 +361,7 @@
 	 * @return bool
 	 */
 	static public function isValidPath($path){
+		$path = str_replace('\\', '/', $path);
 		if(!$path || $path[0]!=='/'){
 			$path='/'.$path;
 		}
```
