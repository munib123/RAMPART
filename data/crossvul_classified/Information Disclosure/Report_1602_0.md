# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1602_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1602_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 170-211 of the vulnerable file.

		// Set header to CSS. Cache for a year (as WordPress does)
		header('Content-Type: text/css; charset=UTF-8');
		header('Expires: ' . gmdate("D, d M Y H:i:s", time() + 31556926) . ' GMT');
		header('Pragma: cache');
		header("Cache-Control: public, max-age=31556926");

		echo $stylesheet;

		die;
	}

	/**
	 * Gets the stylesheet with the parsed style name, then returns it.
	 *
	 * @since 2.2.8
	 * @param string $styleName
	 * @return string $stylesheet
	 */
	public static function getStylesheet($styleName)
	{
		// Get custom stylesheet, of the default stylesheet if the custom stylesheet does not exist
		$stylesheet = get_option($styleName, '');

		if (strlen($stylesheet) <= 0)
		{
			$stylesheetFile = SlideshowPluginMain::getPluginPath() . DIRECTORY_SEPARATOR . 'style' . DIRECTORY_SEPARATOR . 'SlideshowPlugin' . DIRECTORY_SEPARATOR . $styleName . '.css';

			if (!file_exists($stylesheetFile))
			{
				$stylesheetFile = SlideshowPluginMain::getPluginPath() . DIRECTORY_SEPARATOR . 'style' . DIRECTORY_SEPARATOR . 'SlideshowPlugin' . DIRECTORY_SEPARATOR . 'style-light.css';
			}

			// Get contents of stylesheet
			ob_start();
			include($stylesheetFile);
			$stylesheet .= ob_get_clean();
		}

		// Replace the URL placeholders with actual URLs and add a unique identifier to separate stylesheets
		$stylesheet = str_replace('%plugin-url%', SlideshowPluginMain::getPluginUrl(), $stylesheet);
		$stylesheet = str_replace('%site-url%', get_bloginfo('url'), $stylesheet);
		$stylesheet = str_replace('%stylesheet-url%', get_stylesheet_directory_uri(), $stylesheet);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -187,10 +187,16 @@
 	 */
 	public static function getStylesheet($styleName)
 	{
-		// Get custom stylesheet, of the default stylesheet if the custom stylesheet does not exist
-		$stylesheet = get_option($styleName, '');
-
-		if (strlen($stylesheet) <= 0)
+		// Get custom style keys
+		$customStyleKeys = array_keys(get_option(SlideshowPluginGeneralSettings::$customStyles, array()));
+
+		// Match $styleName against custom style keys
+		if (in_array($styleName, $customStyleKeys))
+		{
+			// Get custom stylesheet
+			$stylesheet = get_option($styleName, '');
+		}
+		else
 		{
 			$stylesheetFile = SlideshowPluginMain::getPluginPath() . DIRECTORY_SEPARATOR . 'style' . DIRECTORY_SEPARATOR . 'SlideshowPlugin' . DIRECTORY_SEPARATOR . $styleName . '.css';
 
@@ -202,7 +208,7 @@
 			// Get contents of stylesheet
 			ob_start();
 			include($stylesheetFile);
-			$stylesheet .= ob_get_clean();
+			$stylesheet = ob_get_clean();
 		}
 
 		// Replace the URL placeholders with actual URLs and add a unique identifier to separate stylesheets
```
