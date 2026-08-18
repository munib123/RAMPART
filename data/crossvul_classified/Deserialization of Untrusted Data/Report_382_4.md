# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 382_4
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `382_4`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 38-78 of the vulnerable file.

 * This is a PHP class that contains static methods for the TCPDF class.<br>
 * @package com.tecnick.tcpdf
 * @author Nicola Asuni
 * @version 1.1.2
 */

/**
 * @class TCPDF_STATIC
 * Static methods used by the TCPDF class.
 * @package com.tecnick.tcpdf
 * @brief PHP class for generating PDF documents without requiring external extensions.
 * @version 1.1.1
 * @author Nicola Asuni - info@tecnick.com
 */
class TCPDF_STATIC {

	/**
	 * Current TCPDF version.
	 * @private static
	 */
	private static $tcpdf_version = '6.2.19';

	/**
	 * String alias for total number of pages.
	 * @public static
	 */
	public static $alias_tot_pages = '{:ptp:}';

	/**
	 * String alias for page number.
	 * @public static
	 */
	public static $alias_num_page = '{:pnp:}';

	/**
	 * String alias for total number of pages in a single group.
	 * @public static
	 */
	public static $alias_group_tot_pages = '{:ptg:}';

	/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,7 +55,7 @@
 	 * Current TCPDF version.
 	 * @private static
 	 */
-	private static $tcpdf_version = '6.2.19';
+	private static $tcpdf_version = '6.2.20';
 
 	/**
 	 * String alias for total number of pages.
@@ -1855,6 +1855,29 @@
 	}
 
 	/**
+	 * Wrapper for file_exists.
+	 * Checks whether a file or directory exists.
+	 * Only allows some protocols and local files.
+	 * @param filename (string) Path to the file or directory. 
+	 * @return Returns TRUE if the file or directory specified by filename exists; FALSE otherwise.  
+	 * @public static
+	 */
+	public static function file_exists($filename) {
+		if (strpos($filename, '://') > 0) {
+			$wrappers = stream_get_wrappers();
+			foreach ($wrappers as $wrapper) {
+				if (($wrapper === 'http') || ($wrapper === 'https')) {
+					continue;
+				}
+				if (stripos($filename, $wrapper.'://') === 0) {
+					return false;
+				}
+			}
+		}
+		return @file_exists($filename);
+	}
+
+	/**
 	 * Reads entire file into a string.
 	 * The file can be also an URL.
 	 * @param $file (string) Name of the file or URL to read.
@@ -1914,8 +1937,10 @@
 		}
 		//
 		$alt = array_unique($alt);
-		//var_dump($alt);exit;//DEBUG
 		foreach ($alt as $path) {
+			if (!self::file_exists($path)) {
+				return false;
+			}
 			$ret = @file_get_contents($path);
 			if ($ret !== false) {
 			    return $ret;
@@ -1948,8 +1973,6 @@
 		}
 		return false;
 	}
-
-    
 
 	/**
 	 * Get ULONG from string (Big Endian 32-bit unsigned integer).
```
