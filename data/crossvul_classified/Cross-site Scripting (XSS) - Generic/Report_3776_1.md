# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3776_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3776_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<?php
/**
 * An abstract base class for the string field types (i.e. Varchar and Text)
 * @package sapphire
 * @subpackage model
 * @author Pete Bacon Darwin
 *
 */
abstract class StringField extends DBField {
	protected $nullifyEmpty = true;

	/**
	 * Construct a string type field with a set of optional parameters
	 * @param $name string The name of the field
	 * @param $options array An array of options e.g. array('nullifyEmpty'=>false).  See {@link StringField::setOptions()} for information on the available options
	 */
	function __construct($name = null, $options = array()) {
		// Workaround: The singleton pattern calls this constructor with true/1 as the second parameter, so we must ignore it
		if(is_array($options)){
			$this->setOptions($options);
		}
		parent::__construct($name);
	}
	
	/**
	 * Update the optional parameters for this field.
	 * @param $options array of options
	 * The options allowed are:
	 *   <ul><li>"nullifyEmpty"
	 *       This is a boolean flag.
	 *       True (the default) means that empty strings are automatically converted to nulls to be stored in the database.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,12 @@
  */
 abstract class StringField extends DBField {
 	protected $nullifyEmpty = true;
+
+	static $casting = array(
+		"LimitCharacters" => "Text",
+		"Lower" => "Text",
+		"Upper" => "Text",
+	);
 
 	/**
 	 * Construct a string type field with a set of optional parameters
```
