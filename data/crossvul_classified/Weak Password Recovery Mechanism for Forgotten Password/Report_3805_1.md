# CrossVul Fix Pair: Weak Password Recovery Mechanism for Forgotten Password in php
**Pair ID:** 3805_1
**Vulnerability Class:** Weak Password Recovery Mechanism for Forgotten Password
**CWE:** CWE-640
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3805_1`)

## Vulnerability Information & PoC

## Description
Weak Password Recovery Mechanism for Forgotten Password - It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password.

## Vulnerable Code
```php
Lines 43-62 of the vulnerable file.

$default_map = $settings['default_map'];
$map_layer = map::base($default_map);
if (isset($map_layer->api_url) AND $map_layer->api_url != '')
{
	Kohana::config_set('settings.api_url', 
		"<script type=\"text/javascript\" src=\"".$map_layer->api_url."\"></script>");
}

// And in case you want to display all maps on one page...
$api_google = $settings['api_google'];
$api_live = $settings['api_live'];
Kohana::config_set('settings.api_url_all', 
	"<script type=\"text/javascript\" src=\"https://dev.virtualearth.net/mapcontrol/mapcontrol.ashx?v=6\"></script>\n"
	."<script type=\"text/javascript\" src=\"https://maps.google.com/maps/api/js?v=3.7&amp;sensor=false\"></script>\n"
	. html::script('https://www.openstreetmap.org/openlayers/OpenStreetMap.js')
);

// Additional Mime Types (KMZ/KML)
Kohana::config_set('mimes.kml', array('text/xml'));
Kohana::config_set('mimes.kmz', array('text/xml'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,3 +60,12 @@
 // Additional Mime Types (KMZ/KML)
 Kohana::config_set('mimes.kml', array('text/xml'));
 Kohana::config_set('mimes.kmz', array('text/xml'));
+
+// Set 'settings.forgot_password_key' if not set already
+if ( ! Kohana::config('settings.forgot_password_secret'))
+{
+	$pool = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+[]{};:,.?`~';
+	$key = text::random($pool, 64);
+	Settings_Model::save_setting('forgot_password_secret', $key);
+	Kohana::config_set('settings.forgot_password_secret', $key);
+}
```
