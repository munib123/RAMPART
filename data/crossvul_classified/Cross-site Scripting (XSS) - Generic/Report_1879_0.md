# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1879_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1879_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-35 of the vulnerable file.

<?php

/**
 * The main WP-Piwik class configures, registers and manages the plugin
 *
 * @author Andr&eacute; Br&auml;kling <webmaster@braekling.de>
 * @package WP_Piwik
 */
class WP_Piwik {

	/**
	 *
	 * @var Runtime environment variables
	 */
	private static $revisionId = 2015092001, $version = '1.0.4', $blog_id, $pluginBasename = NULL, $logger, $settings, $request;

	/**
	 * Constructor class to configure and register all WP-Piwik components
	 */
	public function __construct() {
		global $blog_id;
		self::$blog_id = (isset ( $blog_id ) ? $blog_id : 'n/a');
		$this->openLogger ();
		$this->openSettings ();
		$this->setup ();
		$this->addFilters ();
		$this->addActions ();
		$this->addShortcodes ();
	}

	/**
	 * Destructor class to finish logging
	 */
	public function __destruct() {
		$this->closeLogger ();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,7 @@
 	 *
 	 * @var Runtime environment variables
 	 */
-	private static $revisionId = 2015092001, $version = '1.0.4', $blog_id, $pluginBasename = NULL, $logger, $settings, $request;
+	private static $revisionId = 2015101201, $version = '1.0.5', $blog_id, $pluginBasename = NULL, $logger, $settings, $request;
 
 	/**
 	 * Constructor class to configure and register all WP-Piwik components
```
