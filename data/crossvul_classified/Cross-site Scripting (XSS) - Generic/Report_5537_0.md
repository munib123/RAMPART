# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5537_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5537_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 159-199 of the vulnerable file.

		}elseif( file_exists( OC::$SERVERROOT."/core/img/$image" )) {
			return OC::$WEBROOT."/core/img/$image";
		}else{
			echo('image not found: image:'.$image.' webroot:'.OC::$WEBROOT.' serverroot:'.OC::$SERVERROOT);
			die();
		}
	}

	/**
	 * @brief get path to icon of file type
	 * @param string $mimetype mimetype
	 * @return string the url
	 *
	 * Returns the path to the image of this file type.
	 */
	public static function mimetypeIcon( $mimetype ) {
		$alias=array('application/xml'=>'code/xml');
		if(isset($alias[$mimetype])) {
			$mimetype=$alias[$mimetype];
		}
		// Replace slash with a minus
		$mimetype = str_replace( "/", "-", $mimetype );

		// Is it a dir?
		if( $mimetype == "dir" ) {
			return OC::$WEBROOT."/core/img/filetypes/folder.png";
		}

		// Icon exists?
		if( file_exists( OC::$SERVERROOT."/core/img/filetypes/$mimetype.png" )) {
			return OC::$WEBROOT."/core/img/filetypes/$mimetype.png";
		}
		//try only the first part of the filetype
		$mimetype=substr($mimetype,0,strpos($mimetype,'-'));
		if( file_exists( OC::$SERVERROOT."/core/img/filetypes/$mimetype.png" )) {
			return OC::$WEBROOT."/core/img/filetypes/$mimetype.png";
		}
		else{
			return OC::$WEBROOT."/core/img/filetypes/file.png";
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,8 +176,9 @@
 		if(isset($alias[$mimetype])) {
 			$mimetype=$alias[$mimetype];
 		}
-		// Replace slash with a minus
+		// Replace slash and backslash with a minus
 		$mimetype = str_replace( "/", "-", $mimetype );
+		$mimetype = str_replace( "\\", "-", $mimetype );
 
 		// Is it a dir?
 		if( $mimetype == "dir" ) {
```
