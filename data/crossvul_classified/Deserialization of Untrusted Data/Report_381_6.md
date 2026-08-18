# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 381_6
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `381_6`)

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
	private static $tcpdf_version = '6.2.16';

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
-	private static $tcpdf_version = '6.2.16';
+	private static $tcpdf_version = '6.2.26';
 
 	/**
 	 * String alias for total number of pages.
@@ -1774,39 +1774,6 @@
 		return $angle;
 	}
 
-
-
-
-
-
-
-
-
-
-
-
-
-
-
-
-
-// ====================================================================================================================
-// REIMPLEMENTED
-// ====================================================================================================================
-
-
-
-
-
-
-
-
-
-
-
-
-
-
 	/**
 	 * Split string by a regular expression.
 	 * This is a wrapper for the preg_split function to avoid the bug: https://bugs.php.net/bug.php?id=45850
@@ -1852,6 +1819,49 @@
 			return false;
 		}
 		return fopen($filename, $mode);
+	}
+
+	/**
+	 * Check if the URL exist.
+	 * @param url (string) URL to check.
+	 * @return Returns TRUE if the URL exists; FALSE otherwise.
+	 * @public static
+	 */
+	public static function url_exists($url) {
+		$crs = curl_init();
+		curl_setopt($crs, CURLOPT_URL, $url);
+		curl_setopt($crs, CURLOPT_NOBODY, true);
+		curl_setopt($crs, CURLOPT_FAILONERROR, true);
+		if ((ini_get('open_basedir') == '') && (!ini_get('safe_mode'))) {
+			curl_setopt($crs, CURLOPT_FOLLOWLOCATION, true);
+		}
+		curl_setopt($crs, CURLOPT_CONNECTTIMEOUT, 5);
+		curl_setopt($crs, CURLOPT_TIMEOUT, 30);
+		curl_setopt($crs, CURLOPT_SSL_VERIFYPEER, false);
+		curl_setopt($crs, CURLOPT_SSL_VERIFYHOST, false);
+		curl_setopt($crs, CURLOPT_USERAGENT, 'tc-lib-file');
+		curl_exec($crs);
+		$code = curl_getinfo($crs, CURLINFO_HTTP_CODE);
+		curl_close($crs);
+		return ($code == 200);
+	}
+
+	/**
+	 * Wrapper for file_exists.
+	 * Checks whether a file or directory exists.
+	 * Only allows some protocols and local files.
+	 * @param filename (string) Path to the file or directory. 
+	 * @return Returns TRUE if the file or directory specified by filename exists; FALSE otherwise.  
+	 * @public static
+	 */
+	public static function file_exists($filename) {
+		if (preg_match('|^https?://|', $filename) == 1) {
+			return self::url_exists($filename);
+		}
+		if (strpos($filename, '://')) {
+			return false; // only support http and https wrappers for security reasons
+		}
+		return @file_exists($filename);
 	}
 
 	/**
@@ -1914,8 +1924,10 @@
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
@@ -1948,8 +1960,6 @@
 		}
 		return false;
 	}
-
-    
 
 	/**
 	 * Get ULONG from string (Big Endian 32-bit unsigned integer).
```
