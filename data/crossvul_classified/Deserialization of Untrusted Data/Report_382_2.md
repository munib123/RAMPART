# CrossVul Fix Pair: Deserialization of Untrusted Data in php
**Pair ID:** 382_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `382_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```php
Lines 53-93 of the vulnerable file.

	 */
	protected static $cache_uniord = array();

	/**
	 * Convert and add the selected TrueType or Type1 font to the fonts folder (that must be writeable).
	 * @param $fontfile (string) Font file (full path).
	 * @param $fonttype (string) Font type. Leave empty for autodetect mode. Valid values are: TrueTypeUnicode, TrueType, Type1, CID0JP = CID-0 Japanese, CID0KR = CID-0 Korean, CID0CS = CID-0 Chinese Simplified, CID0CT = CID-0 Chinese Traditional.
	 * @param $enc (string) Name of the encoding table to use. Leave empty for default mode. Omit this parameter for TrueType Unicode and symbolic fonts like Symbol or ZapfDingBats.
	 * @param $flags (int) Unsigned 32-bit integer containing flags specifying various characteristics of the font (PDF32000:2008 - 9.8.2 Font Descriptor Flags): +1 for fixed font; +4 for symbol or +32 for non-symbol; +64 for italic. Fixed and Italic mode are generally autodetected so you have to set it to 32 = non-symbolic font (default) or 4 = symbolic font.
	 * @param $outpath (string) Output path for generated font files (must be writeable by the web server). Leave empty for default font folder.
	 * @param $platid (int) Platform ID for CMAP table to extract (when building a Unicode font for Windows this value should be 3, for Macintosh should be 1).
	 * @param $encid (int) Encoding ID for CMAP table to extract (when building a Unicode font for Windows this value should be 1, for Macintosh should be 0). When Platform ID is 3, legal values for Encoding ID are: 0=Symbol, 1=Unicode, 2=ShiftJIS, 3=PRC, 4=Big5, 5=Wansung, 6=Johab, 7=Reserved, 8=Reserved, 9=Reserved, 10=UCS-4.
	 * @param $addcbbox (boolean) If true includes the character bounding box information on the php font file.
	 * @param $link (boolean) If true link to system font instead of copying the font data (not transportable) - Note: do not work with Type1 fonts.
	 * @return (string) TCPDF font name or boolean false in case of error.
	 * @author Nicola Asuni
	 * @since 5.9.123 (2010-09-30)
	 * @public static
	 */
	public static function addTTFfont($fontfile, $fonttype='', $enc='', $flags=32, $outpath='', $platid=3, $encid=1, $addcbbox=false, $link=false) {
		if (!file_exists($fontfile)) {
			// Could not find file
			return false;
		}
		// font metrics
		$fmetric = array();
		// build new font name for TCPDF compatibility
		$font_path_parts = pathinfo($fontfile);
		if (!isset($font_path_parts['filename'])) {
			$font_path_parts['filename'] = substr($font_path_parts['basename'], 0, -(strlen($font_path_parts['extension']) + 1));
		}
		$font_name = strtolower($font_path_parts['filename']);
		$font_name = preg_replace('/[^a-z0-9_]/', '', $font_name);
		$search  = array('bold', 'oblique', 'italic', 'regular');
		$replace = array('b', 'i', 'i', '');
		$font_name = str_replace($search, $replace, $font_name);
		if (empty($font_name)) {
			// set generic name
			$font_name = 'tcpdffont';
		}
		// set output path
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -70,7 +70,7 @@
 	 * @public static
 	 */
 	public static function addTTFfont($fontfile, $fonttype='', $enc='', $flags=32, $outpath='', $platid=3, $encid=1, $addcbbox=false, $link=false) {
-		if (!file_exists($fontfile)) {
+		if (!TCPDF_STATIC::file_exists($fontfile)) {
 			// Could not find file
 			return false;
 		}
@@ -95,7 +95,7 @@
 			$outpath = self::_getfontpath();
 		}
 		// check if this font already exist
-		if (@file_exists($outpath.$font_name.'.php')) {
+		if (@TCPDF_STATIC::file_exists($outpath.$font_name.'.php')) {
 			// this font already exist (delete it from fonts folder to rebuild it)
 			return $font_name;
 		}
@@ -1543,11 +1543,11 @@
 	public static function getFontFullPath($file, $fontdir=false) {
 		$fontfile = '';
 		// search files on various directories
-		if (($fontdir !== false) AND @file_exists($fontdir.$file)) {
+		if (($fontdir !== false) AND @TCPDF_STATIC::file_exists($fontdir.$file)) {
 			$fontfile = $fontdir.$file;
-		} elseif (@file_exists(self::_getfontpath().$file)) {
+		} elseif (@TCPDF_STATIC::file_exists(self::_getfontpath().$file)) {
 			$fontfile = self::_getfontpath().$file;
-		} elseif (@file_exists($file)) {
+		} elseif (@TCPDF_STATIC::file_exists($file)) {
 			$fontfile = $file;
 		}
 		return $fontfile;
```
