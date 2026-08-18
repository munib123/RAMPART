# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3749_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3749_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 62-102 of the vulnerable file.

	 */
	public static function scanFile($path){
		$file=OC_Filesystem::getLocalFile($path);
		if(!self::isMusic($path)){
			return;
		}
		if(!self::$getID3){
			self::$getID3=@new getID3();
			self::$getID3->encoding='UTF-8';
		}
		$data=@self::$getID3->analyze($file);
		getid3_lib::CopyTagsToComments($data);
		if(!isset($data['comments'])){
			OCP\Util::writeLog('media',"error reading id3 tags in '$file'",OCP\Util::WARN);
			return;
		}
		if(!isset($data['comments']['artist'])){
			OCP\Util::writeLog('media',"error reading artist tag in '$file'",OCP\Util::WARN);
			$artist='unknown';
		}else{
			$artist=stripslashes($data['comments']['artist'][0]);
		}
		if(!isset($data['comments']['album'])){
			OCP\Util::writeLog('media',"error reading album tag in '$file'",OCP\Util::WARN);
			$album='unknown';
		}else{
			$album=stripslashes($data['comments']['album'][0]);
		}
		if(!isset($data['comments']['title'])){
			OCP\Util::writeLog('media',"error reading title tag in '$file'",OCP\Util::WARN);
			$title='unknown';
		}else{
			$title=stripslashes($data['comments']['title'][0]);
		}
		$size=$data['filesize'];
		if (isset($data['comments']['track']))
		{
			$track = $data['comments']['track'][0];
		}
		else if (isset($data['comments']['track_number']))
		{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,19 +79,19 @@
 			OCP\Util::writeLog('media',"error reading artist tag in '$file'",OCP\Util::WARN);
 			$artist='unknown';
 		}else{
-			$artist=stripslashes($data['comments']['artist'][0]);
+			$artist=strip_tags(stripslashes($data['comments']['artist'][0]));
 		}
 		if(!isset($data['comments']['album'])){
 			OCP\Util::writeLog('media',"error reading album tag in '$file'",OCP\Util::WARN);
 			$album='unknown';
 		}else{
-			$album=stripslashes($data['comments']['album'][0]);
+			$album=strip_tags(stripslashes($data['comments']['album'][0]));
 		}
 		if(!isset($data['comments']['title'])){
 			OCP\Util::writeLog('media',"error reading title tag in '$file'",OCP\Util::WARN);
 			$title='unknown';
 		}else{
-			$title=stripslashes($data['comments']['title'][0]);
+			$title=strip_tags(stripslashes($data['comments']['title'][0]));
 		}
 		$size=$data['filesize'];
 		if (isset($data['comments']['track']))
```
