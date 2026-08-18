# CrossVul Fix Pair: Data Processing Errors in php
**Pair ID:** 2327_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2327_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```php
Lines 22-62 of the vulnerable file.

 * @copyright Copyright (C) 2002 - 2014  MantisBT Team - mantisbt-dev@lists.sourceforge.net
 * @link http://www.mantisbt.org
 */

/**
 * requires MantisPlugin.class.php
 */
require_once( config_get( 'class_path' ) . 'MantisPlugin.class.php' );

/**
 * XmlImportExportPlugin Class
 */
class XmlImportExportPlugin extends MantisPlugin {

	/**
	 *  A method that populates the plugin information and minimum requirements.
	 */
	function register( ) {
		$this->name = plugin_lang_get( 'title' );
		$this->description = plugin_lang_get( 'description' );
		$this->page = '';

		$this->version = '1.0';
		$this->requires = array(
			'MantisCore' => '1.2.0',
		);

		$this->author = 'MantisBT Team';
		$this->contact = 'mantisbt-dev@lists.sourceforge.net';
		$this->url = 'http://www.mantisbt.org';
	}

	/**
	 * Default plugin configuration.
	 */
	function hooks( ) {
		$hooks = array(
			'EVENT_MENU_MANAGE' => 'import_issues_menu',
			'EVENT_MENU_FILTER' => 'export_issues_menu',
		);
		return $hooks;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,7 +39,7 @@
 	function register( ) {
 		$this->name = plugin_lang_get( 'title' );
 		$this->description = plugin_lang_get( 'description' );
-		$this->page = '';
+		$this->page = "config_page";
 
 		$this->version = '1.0';
 		$this->requires = array(
@@ -54,6 +54,17 @@
 	/**
 	 * Default plugin configuration.
 	 */
+	public function config() {
+		return array(
+			"import_threshold" => ADMINISTRATOR,
+			"export_threshold" => DEVELOPER,
+		);
+	}
+
+	/**
+	 * Plugin hooks
+	 * @return array
+	 */
 	function hooks( ) {
 		$hooks = array(
 			'EVENT_MENU_MANAGE' => 'import_issues_menu',
@@ -67,6 +78,9 @@
 	}
 
 	function export_issues_menu( ) {
+		if( !access_has_project_level( plugin_config_get( 'export_threshold' ) ) ) {
+			return array();
+		}
 		return array( '<a href="' . plugin_page( 'export' ) . '">' . plugin_lang_get( 'export' ) . '</a>', );
 	}
 
```
