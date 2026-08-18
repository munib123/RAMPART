# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 381_5
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `381_5`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 144-189 of the vulnerable file.

	 * return image JPEG image object.
	 * @public static
	 */
	public static function _toJPEG($image, $quality, $tempfile) {
		imagejpeg($image, $tempfile, $quality);
		imagedestroy($image);
		$retvars = self::_parsejpeg($tempfile);
		// tidy up by removing temporary image
		unlink($tempfile);
		return $retvars;
	}

	/**
	 * Extract info from a JPEG file without using the GD library.
	 * @param $file (string) image file to parse
	 * @return array structure containing the image data
	 * @public static
	 */
	public static function _parsejpeg($file) {
		// check if is a local file
		if (!@file_exists($file)) {
			// try to encode spaces on filename
			$tfile = str_replace(' ', '%20', $file);
			if (@file_exists($tfile)) {
				$file = $tfile;
			}
		}
		$a = getimagesize($file);
		if (empty($a)) {
			//Missing or incorrect image file
			return false;
		}
		if ($a[2] != 2) {
			// Not a JPEG file
			return false;
		}
		// bits per pixel
		$bpc = isset($a['bits']) ? intval($a['bits']) : 8;
		// number of image channels
		if (!isset($a['channels'])) {
			$channels = 3;
		} else {
			$channels = intval($a['channels']);
		}
		// default colour space
		switch ($channels) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -161,12 +161,8 @@
 	 */
 	public static function _parsejpeg($file) {
 		// check if is a local file
-		if (!@file_exists($file)) {
-			// try to encode spaces on filename
-			$tfile = str_replace(' ', '%20', $file);
-			if (@file_exists($tfile)) {
-				$file = $tfile;
-			}
+		if (!@TCPDF_STATIC::file_exists($file)) {
+			return false;
 		}
 		$a = getimagesize($file);
 		if (empty($a)) {
```
