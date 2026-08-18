# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3776_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3776_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 10-50 of the vulnerable file.

 * @package sapphire
 * @subpackage model
 */
class HTMLText extends Text {
	
	public static $escape_type = 'xml';
	
	/**
	 * Limit this field's content by a number of characters.
	 * This makes use of strip_tags() to avoid malforming the
	 * HTML tags in the string of text.
	 *
	 * @param int $limit Number of characters to limit by
	 * @param string $add Ellipsis to add to the end of truncated string
	 * @return string
	 */
	function LimitCharacters($limit = 20, $add = "...") {
		$value = trim(strip_tags($this->value));
		return (strlen($value) > $limit) ? substr($value, 0, $limit) . $add : $value;
	}

	/**
	 * Create a summary of the content. This will be some section of the first paragraph, limited by
	 * $maxWords. All internal tags are stripped out - the return value is a string
	 * 
	 * This is sort of the HTML aware equivilent to Text#Summary, although the logic for summarising is not exactly the same
	 * 
	 * @param int $maxWords Maximum number of words to return - may return less, but never more. Pass -1 for no limit
	 * @param int $flex Number of words to search through when looking for a nice cut point 
	 * @param string $add What to add to the end of the summary if we cut at a less-than-ideal cut point
	 * @return string A nice(ish) summary with no html tags (but possibly still some html entities)
	 * 
	 * @see sapphire/core/model/fieldtypes/Text#Summary($maxWords)
	 */
	public function Summary($maxWords = 50, $flex = 15, $add = '...') {
		$str = false;

		/* First we need the text of the first paragraph, without tags. Try using SimpleXML first */
		if (class_exists('SimpleXMLElement')) {
			$doc = new DOMDocument();
			
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,25 @@
 		$value = trim(strip_tags($this->value));
 		return (strlen($value) > $limit) ? substr($value, 0, $limit) . $add : $value;
 	}
+
+	static $casting = array(
+		"AbsoluteLinks" => "HTMLText",
+		"BigSummary" => "HTMLText",
+		"ContextSummary" => "HTMLText",
+		"FirstParagraph" => "HTMLText",
+		"FirstSentence" => "HTMLText",
+		"LimitCharacters" => "HTMLText",
+		"LimitSentences" => "HTMLText",
+		"Lower" => "HTMLText",
+		"LowerCase" => "HTMLText",
+		"Summary" => "HTMLText",
+		"Upper" => "HTMLText",
+		"UpperCase" => "HTMLText",
+		'EscapeXML' => 'HTMLText',
+		'LimitWordCount' => 'HTMLText',
+		'LimitWordCountXML' => 'HTMLText',
+		'NoHTML' => 'Text',
+	);
 
 	/**
 	 * Create a summary of the content. This will be some section of the first paragraph, limited by
```
