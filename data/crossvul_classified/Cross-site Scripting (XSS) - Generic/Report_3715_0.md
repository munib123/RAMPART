# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3715_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3715_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-40 of the vulnerable file.

<?php
/**
 * Layout for the admin interface.
 *
 * PHP version 5
 * LICENSE: This source file is subject to LGPL license
 * that is available through the world-wide-web at the following URI:
 * http://www.gnu.org/copyleft/lesser.html
 * @author     Ushahidi Team <team@ushahidi.com>
 * @package    Ushahidi - https://github.com/ushahidi/Ushahidi_Web
 * @copyright  Ushahidi - http://www.ushahidi.com
 * @license    http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License (LGPL)
 */
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=7" />
	<title><?php echo $site_name ?></title>
	<?php
	echo html::stylesheet(url::file_loc('css').'media/css/admin/all', '', TRUE);
	echo html::stylesheet(url::file_loc('css').'media/css/jquery-ui-themeroller', '', TRUE);
	echo "<!--[if lt IE 7]>".
		html::stylesheet(url::file_loc('css').'media/css/ie6', '', TRUE)
		."<![endif]-->";

	// Load OpenLayers
	if ($map_enabled)
	{
		echo html::script(url::file_loc('js').'media/js/OpenLayers', TRUE);
		echo html::script(url::file_loc('js').'media/js/ushahidi', TRUE);
		echo $api_url . "\n";
		echo "<script type=\"text/javascript\">
			OpenLayers.ImgPath = '".url::file_loc('img').'media/img/openlayers/'."';
			</script>";
		echo html::stylesheet(url::file_loc('css').'media/css/openlayers','',TRUE);
	}

	// Load jQuery
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,7 @@
 <head>
 	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
 	<meta http-equiv="X-UA-Compatible" content="IE=7" />
-	<title><?php echo $site_name ?></title>
+	<title><?php echo html::specialchars($site_name) ?></title>
 	<?php
 	echo html::stylesheet(url::file_loc('css').'media/css/admin/all', '', TRUE);
 	echo html::stylesheet(url::file_loc('css').'media/css/jquery-ui-themeroller', '', TRUE);
```
