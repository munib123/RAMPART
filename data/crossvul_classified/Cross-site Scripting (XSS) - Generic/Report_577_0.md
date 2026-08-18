# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 577_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `577_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 726-766 of the vulnerable file.

	'wp-admin/js/bookmarklet.js',
	'wp-admin/js/bookmarklet.min.js',
	'wp-admin/js/press-this.js',
	'wp-admin/js/press-this.min.js',
	'wp-includes/js/mediaelement/background.png',
	'wp-includes/js/mediaelement/bigplay.png',
	'wp-includes/js/mediaelement/bigplay.svg',
	'wp-includes/js/mediaelement/controls.png',
	'wp-includes/js/mediaelement/controls.svg',
	'wp-includes/js/mediaelement/flashmediaelement.swf',
	'wp-includes/js/mediaelement/froogaloop.min.js',
	'wp-includes/js/mediaelement/jumpforward.png',
	'wp-includes/js/mediaelement/loading.gif',
	'wp-includes/js/mediaelement/silverlightmediaelement.xap',
	'wp-includes/js/mediaelement/skipback.png',
	'wp-includes/js/plupload/plupload.flash.swf',
	'wp-includes/js/plupload/plupload.full.min.js',
	'wp-includes/js/plupload/plupload.silverlight.xap',
	'wp-includes/js/swfupload/plugins',
	'wp-includes/js/swfupload/swfupload.swf',
);

/**
 * Stores new files in wp-content to copy
 *
 * The contents of this array indicate any new bundled plugins/themes which
 * should be installed with the WordPress Upgrade. These items will not be
 * re-installed in future upgrades, this behaviour is controlled by the
 * introduced version present here being older than the current installed version.
 *
 * The content of this array should follow the following format:
 * Filename (relative to wp-content) => Introduced version
 * Directories should be noted by suffixing it with a trailing slash (/)
 *
 * @since 3.2.0
 * @since 4.7.0 New themes were not automatically installed for 4.4-4.6 on
 *              upgrade. New themes are now installed again. To disable new
 *              themes from being installed on upgrade, explicitly define
 *              CORE_UPGRADE_SKIP_NEW_BUNDLED as false.
 * @global array $_new_bundled_files
 * @var array
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -743,6 +743,42 @@
 	'wp-includes/js/plupload/plupload.silverlight.xap',
 	'wp-includes/js/swfupload/plugins',
 	'wp-includes/js/swfupload/swfupload.swf',
+	// 4.9.2
+	'wp-includes/js/mediaelement/lang',
+	'wp-includes/js/mediaelement/lang/ca.js',
+	'wp-includes/js/mediaelement/lang/cs.js',
+	'wp-includes/js/mediaelement/lang/de.js',
+	'wp-includes/js/mediaelement/lang/es.js',
+	'wp-includes/js/mediaelement/lang/fa.js',
+	'wp-includes/js/mediaelement/lang/fr.js',
+	'wp-includes/js/mediaelement/lang/hr.js',
+	'wp-includes/js/mediaelement/lang/hu.js',
+	'wp-includes/js/mediaelement/lang/it.js',
+	'wp-includes/js/mediaelement/lang/ja.js',
+	'wp-includes/js/mediaelement/lang/ko.js',
+	'wp-includes/js/mediaelement/lang/nl.js',
+	'wp-includes/js/mediaelement/lang/pl.js',
+	'wp-includes/js/mediaelement/lang/pt.js',
+	'wp-includes/js/mediaelement/lang/ro.js',
+	'wp-includes/js/mediaelement/lang/ru.js',
+	'wp-includes/js/mediaelement/lang/sk.js',
+	'wp-includes/js/mediaelement/lang/sv.js',
+	'wp-includes/js/mediaelement/lang/uk.js',
+	'wp-includes/js/mediaelement/lang/zh-cn.js',
+	'wp-includes/js/mediaelement/lang/zh.js',
+	'wp-includes/js/mediaelement/mediaelement-flash-audio-ogg.swf',
+	'wp-includes/js/mediaelement/mediaelement-flash-audio.swf',
+	'wp-includes/js/mediaelement/mediaelement-flash-video-hls.swf',
+	'wp-includes/js/mediaelement/mediaelement-flash-video-mdash.swf',
+	'wp-includes/js/mediaelement/mediaelement-flash-video.swf',
+	'wp-includes/js/mediaelement/renderers/dailymotion.js',
+	'wp-includes/js/mediaelement/renderers/dailymotion.min.js',
+	'wp-includes/js/mediaelement/renderers/facebook.js',
+	'wp-includes/js/mediaelement/renderers/facebook.min.js',
+	'wp-includes/js/mediaelement/renderers/soundcloud.js',
+	'wp-includes/js/mediaelement/renderers/soundcloud.min.js',
+	'wp-includes/js/mediaelement/renderers/twitch.js',
+	'wp-includes/js/mediaelement/renderers/twitch.min.js',
 );
 
 /**
```
