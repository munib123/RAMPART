# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3776_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3776_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-33 of the vulnerable file.

<?php
/**
 * Class Varchar represents a variable-length string of up to 255 characters, designed to store raw text
 * 
 * @see HTMLText
 * @see HTMLVarchar
 * @see Text
 * 
 * @package sapphire
 * @subpackage model
 */
class Varchar extends StringField {
	
	protected $size;
	 
 	/**
 	 * Construct a new short text field
 	 * 
 	 * @param $name string The name of the field
 	 * @param $size int The maximum size of the field, in terms of characters
 	 * @param $options array Optional parameters, e.g. array("nullifyEmpty"=>false). See {@link StringField::setOptions()} for information on the available options
 	 * @return unknown_type
 	 */
 	function __construct($name, $size = 50, $options = array()) {
		$this->size = $size ? $size : 50;
		parent::__construct($name, $options);
	}
	
 	/**
 	 * (non-PHPdoc)
 	 * @see DBField::requireField()
 	 */
	function requireField() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,11 @@
  * @subpackage model
  */
 class Varchar extends StringField {
+
+	static $casting = array(
+		"Initial" => "Text",
+		"URL" => "Text",
+	);
 	
 	protected $size;
 	 
```
