# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3550_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3550_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 354-394 of the vulnerable file.

		foreach(array('Content', 'Layout') as $subtemplate) {
			if(isset($this->chosenTemplates[$subtemplate])) {
				$subtemplateViewer = new SSViewer($this->chosenTemplates[$subtemplate]);
				$item = $item->customise(array(
					$subtemplate => $subtemplateViewer->process($item)
				));
			}
		}
		
		$itemStack = array();
		$val = "";

		include($cacheFile);

		$output = $val;		
		$output = Requirements::includeInHTML($template, $output);
		
		array_pop(SSViewer::$topLevel);

		if(isset($_GET['debug_profile'])) Profiler::unmark("SSViewer::process", " for $template");
		
		// If we have our crazy base tag, then fix # links referencing the current page.
		if(strpos($output, '<base') !== false) {
			if(SSViewer::$options['rewriteHashlinks'] === 'php') {
				$thisURLRelativeToBase = "<?php echo strip_tags(\$_SERVER['REQUEST_URI']); ?>"; 
			} else {
				$thisURLRelativeToBase = strip_tags($_SERVER['REQUEST_URI']); 
			}
			$output = preg_replace('/(<a[^>+]href *= *)"#/i', '\\1"' . $thisURLRelativeToBase . '#', $output);
		}	
		
		return $output;
	}

	static function parseTemplateContent($content, $template="") {			
		// Add template filename comments on dev sites

		if(Director::isDev() && self::$source_file_comments && $template && stripos($content, "<?xml") === false) {
			// If this template is a full HTML page, then put the comments just inside the HTML tag to prevent any IE glitches
			if(stripos($content, "<html") !== false) {
				$content = preg_replace('/(<html[^>]*>)/i', "\\1<!-- template $template -->", $content);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -371,16 +371,18 @@
 		array_pop(SSViewer::$topLevel);
 
 		if(isset($_GET['debug_profile'])) Profiler::unmark("SSViewer::process", " for $template");
-		
+				
 		// If we have our crazy base tag, then fix # links referencing the current page.
-		if(strpos($output, '<base') !== false) {
-			if(SSViewer::$options['rewriteHashlinks'] === 'php') {
-				$thisURLRelativeToBase = "<?php echo strip_tags(\$_SERVER['REQUEST_URI']); ?>"; 
-			} else {
-				$thisURLRelativeToBase = strip_tags($_SERVER['REQUEST_URI']); 
-			}
-			$output = preg_replace('/(<a[^>+]href *= *)"#/i', '\\1"' . $thisURLRelativeToBase . '#', $output);
-		}	
+		if(SSViewer::$options['rewriteHashlinks']) {
+			if(strpos($output, '<base') !== false) {
+				if(SSViewer::$options['rewriteHashlinks'] === 'php') {
+					$thisURLRelativeToBase = "<?php echo strip_tags(\$_SERVER['REQUEST_URI']); ?>"; 
+				} else {
+					$thisURLRelativeToBase = strip_tags($_SERVER['REQUEST_URI']); 
+				}
+				$output = preg_replace('/(<a[^>]+href *= *)"#/i', '\\1"' . $thisURLRelativeToBase . '#', $output);
+			}
+		}
 		
 		return $output;
 	}
```
