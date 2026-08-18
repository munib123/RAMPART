# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 5784_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5784_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 43-83 of the vulnerable file.

	 */
	public static function canUpload($file, &$err)
	{
		$params = JComponentHelper::getParams('com_media');

		if (empty($file['name'])) {
			$err = 'COM_MEDIA_ERROR_UPLOAD_INPUT';
			return false;
		}

		jimport('joomla.filesystem.file');
		if ($file['name'] !== JFile::makesafe($file['name'])) {
			$err = 'COM_MEDIA_ERROR_WARNFILENAME';
			return false;
		}

		$format = strtolower(JFile::getExt($file['name']));

		$allowable = explode(',', $params->get('upload_extensions'));
		$ignored = explode(',', $params->get('ignore_extensions'));
		if (!in_array($format, $allowable) && !in_array($format, $ignored))
		{
			$err = 'COM_MEDIA_ERROR_WARNFILETYPE';
			return false;
		}

		$maxSize = (int) ($params->get('upload_maxsize', 0) * 1024 * 1024);
		if ($maxSize > 0 && (int) $file['size'] > $maxSize)
		{
			$err = 'COM_MEDIA_ERROR_WARNFILETOOLARGE';
			return false;
		}

		$user = JFactory::getUser();
		$imginfo = null;
		if ($params->get('restrict_uploads', 1)) {
			$images = explode(',', $params->get('image_extensions'));
			if (in_array($format, $images)) { // if its an image run it through getimagesize
				// if tmp_name is empty, then the file was bigger than the PHP limit
				if (!empty($file['tmp_name'])) {
					if (($imginfo = getimagesize($file['tmp_name'])) === FALSE) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,7 +60,7 @@
 
 		$allowable = explode(',', $params->get('upload_extensions'));
 		$ignored = explode(',', $params->get('ignore_extensions'));
-		if (!in_array($format, $allowable) && !in_array($format, $ignored))
+		if ($format == '' || $format == false || (!in_array($format, $allowable) && !in_array($format, $ignored)))
 		{
 			$err = 'COM_MEDIA_ERROR_WARNFILETYPE';
 			return false;
```
