# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2797_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2797_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 112-152 of the vulnerable file.

		'TreeTitle' => 'HTMLText'
	);

	/**
	 * @config
	 * @var array List of allowed file extensions, enforced through {@link validate()}.
	 *
	 * Note: if you modify this, you should also change a configuration file in the assets directory.
	 * Otherwise, the files will be able to be uploaded but they won't be able to be served by the
	 * webserver.
	 *
	 *  - If you are running Apache you will need to change assets/.htaccess
	 *  - If you are running IIS you will need to change assets/web.config
	 *
	 * Instructions for the change you need to make are included in a comment in the config file.
	 */
	private static $allowed_extensions = array(
		'','ace','arc','arj','asf','au','avi','bmp','bz2','cab','cda','css','csv','dmg','doc','docx','dotx','dotm',
		'flv','gif','gpx','gz','hqx','ico','jar','jpeg','jpg','js','kml', 'm4a','m4v',
		'mid','midi','mkv','mov','mp3','mp4','mpa','mpeg','mpg','ogg','ogv','pages','pcx','pdf','pkg',
		'png','pps','ppt','pptx','potx','potm','ra','ram','rm','rtf','sit','sitx', 'svg', 'tar','tgz','tif','tiff',
		'txt','wav','webm','wma','wmv','xls','xlsx','xltx','xltm','zip','zipx',
	);

	/**
	 * @config
	 * @var array Category identifiers mapped to commonly used extensions.
	 */
	private static $app_categories = array(
		'audio' => array(
			"aif" ,"au" ,"mid" ,"midi" ,"mp3" ,"ra" ,"ram" ,"rm","mp3" ,"wav" ,"m4a" ,"snd" ,"aifc" ,"aiff" ,"wma",
			"apl", "avr" ,"cda" ,"ogg"
		),
		'mov' => array(
			"mpeg" ,"mpg" ,"mp4" ,"m1v" ,"mp2" ,"mpa" ,"mpe" ,"ifo" ,"vob","avi" ,"wmv" ,"asf" ,"m2v" ,"qt", "ogv", "webm"
		),
		'zip' => array(
			"arc" ,"rar" ,"tar" ,"gz" ,"tgz" ,"bz2" ,"dmg" ,"jar","ace" ,"arj" ,"bz" ,"cab"
		),
		'image' => array(
			"bmp" ,"gif" ,"jpg" ,"jpeg" ,"pcx" ,"tif" ,"png" ,"alpha","als" ,"cel" ,"icon" ,"ico" ,"ps"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,7 +129,7 @@
 		'','ace','arc','arj','asf','au','avi','bmp','bz2','cab','cda','css','csv','dmg','doc','docx','dotx','dotm',
 		'flv','gif','gpx','gz','hqx','ico','jar','jpeg','jpg','js','kml', 'm4a','m4v',
 		'mid','midi','mkv','mov','mp3','mp4','mpa','mpeg','mpg','ogg','ogv','pages','pcx','pdf','pkg',
-		'png','pps','ppt','pptx','potx','potm','ra','ram','rm','rtf','sit','sitx', 'svg', 'tar','tgz','tif','tiff',
+		'png','pps','ppt','pptx','potx','potm','ra','ram','rm','rtf','sit','sitx', 'tar','tgz','tif','tiff',
 		'txt','wav','webm','wma','wmv','xls','xlsx','xltx','xltm','zip','zipx',
 	);
 
```
