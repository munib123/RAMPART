# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 4144_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4144_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 136-163 of the vulnerable file.

	$path = SOYSHOP_SITE_DIRECTORY;
	$url = SOYSHOP_SITE_URL;
}


// Documentation for connector options:
// https://github.com/Studio-42/elFinder/wiki/Connector-configuration-options
$opts = array(
	// 'debug' => true,
	'roots' => array(
		// Items volume
		array(
			'driver'        => 'LocalFileSystem',           // driver for accessing file system (REQUIRED)
			'path'          => $path, 		                // path to files (REQUIRED)
			'URL'           => $url, 						// URL to files (REQUIRED)
			//'trashHash'     => 't1_Lw',                     // elFinder's hash of trash folder
			'winHashFix'    => DIRECTORY_SEPARATOR !== '/', // to make hash same to Linux one on windows too
			'uploadDeny'    => array('all'),                // All Mimetypes not allowed to upload
			'uploadAllow'   => array('image', 'text/plain', 'text/css', 'application/zip', 'application/epub+zip','application/pdf'),// Mimetype `image` and `text/plain` allowed to upload
			'uploadOrder'   => array('deny', 'allow'),      // allowed Mimetype `image` and `text/plain` only
			'accessControl' => 'access'                     // disable and hide dot starting files (OPTIONAL)
		),
	)
);

// run elFinder
$connector = new elFinderConnector(new elFinder($opts));
$connector->run();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -153,7 +153,17 @@
 			'uploadDeny'    => array('all'),                // All Mimetypes not allowed to upload
 			'uploadAllow'   => array('image', 'text/plain', 'text/css', 'application/zip', 'application/epub+zip','application/pdf'),// Mimetype `image` and `text/plain` allowed to upload
 			'uploadOrder'   => array('deny', 'allow'),      // allowed Mimetype `image` and `text/plain` only
-			'accessControl' => 'access'                     // disable and hide dot starting files (OPTIONAL)
+			'accessControl' => 'access',                     // disable and hide dot starting files (OPTIONAL)
+			'attributes' => array(
+                                //フロントコントローラー
+                                array(
+                                      	'pattern' => '/\\.php(\\.old(\\.[0-9][0-9])?)?$/',
+                                        'read' => false,
+                                        'write' => false,
+                                        'locked' => true,
+                                        'hidden' => true,
+                                ),
+                        )
 		),
 	)
 );
```
