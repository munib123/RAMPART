# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3776_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3776_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-40 of the vulnerable file.

<?php
/**
 * Represents a variable-length string of up to 2 megabytes, designed to store raw text
 * 
 * Example definition via {@link DataObject::$db}:
 * <code>
 * static $db = array(
 * 	"MyDescription" => "Text",
 * );
 * </code>
 * 
 * @see HTMLText
 * @see HTMLVarchar
 * @see Varchar
 * 
 * @package sapphire
 * @subpackage model
 */
class Text extends StringField {
	static $casting = array(
		"AbsoluteLinks" => "HTMLText",
	);
	
 	/**
 	 * (non-PHPdoc)
 	 * @see DBField::requireField()
 	 */
	function requireField() {
		$parts=Array('datatype'=>'mediumtext', 'character set'=>'utf8', 'collate'=>'utf8_general_ci', 'arrayValue'=>$this->arrayValue);
		$values=Array('type'=>'text', 'parts'=>$parts);
		DB::requireField($this->tableName, $this->name, $values, $this->default);
	}
	
	/**
	 * Limit this field's content by a number of words.
	 * CAUTION: This is not XML safe. Please use
	 * {@link LimitWordCountXML()} instead.
	 *
	 * @param int $numWords Number of words to limit by
	 * @param string $add Ellipsis to add to the end of truncated string
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,8 +17,20 @@
  * @subpackage model
  */
 class Text extends StringField {
+
 	static $casting = array(
-		"AbsoluteLinks" => "HTMLText",
+		"AbsoluteLinks" => "Text",
+		"BigSummary" => "Text",
+		"ContextSummary" => "Text",
+		"FirstParagraph" => "Text",
+		"FirstSentence" => "Text",
+		"LimitCharacters" => "Text",
+		"LimitSentences" => "Text",
+		"Summary" => "Text",
+		'EscapeXML' => 'Text',
+		'LimitWordCount' => 'Text',
+		'LimitWordCountXML' => 'HTMLText',
+		'NoHTML' => 'Text',
 	);
 	
  	/**
```
