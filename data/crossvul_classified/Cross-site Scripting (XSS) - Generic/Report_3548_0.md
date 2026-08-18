# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3548_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3548_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 422-462 of the vulnerable file.

			}
		}
		
		$itemStack = array();
		$val = "";
		$valStack = array();
		
		include($cacheFile);

		$output = $val;		
		$output = Requirements::includeInHTML($template, $output);
		
		array_pop(SSViewer::$topLevel);

		if(isset($_GET['debug_profile'])) Profiler::unmark("SSViewer::process", " for $template");
		
		// If we have our crazy base tag, then fix # links referencing the current page.
		if($this->rewriteHashlinks && self::$options['rewriteHashlinks']) {
			if(strpos($output, '<base') !== false) {
				if(SSViewer::$options['rewriteHashlinks'] === 'php') { 
					$thisURLRelativeToBase = "<?php echo \$_SERVER['REQUEST_URI']; ?>"; 
				} else { 
					$thisURLRelativeToBase = Director::makeRelative(Director::absoluteURL($_SERVER['REQUEST_URI'])); 
				}
				$output = preg_replace('/(<a[^>]+href *= *)"#/i', '\\1"' . $thisURLRelativeToBase . '#', $output);
			}
		}

		return $output;
	}

	static function parseTemplateContent($content, $template="") {			
		// Remove UTF-8 byte order mark:
		// This is only necessary if you don't have zend-multibyte enabled.
		if(substr($content, 0,3) == pack("CCC", 0xef, 0xbb, 0xbf)) {
			$content = substr($content, 3);
		}

		// Add template filename comments on dev sites
		if(Director::isDev() && self::$source_file_comments && $template && stripos($content, "<?xml") === false) {
			// If this template is a full HTML page, then put the comments just inside the HTML tag to prevent any IE glitches
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -439,9 +439,10 @@
 		if($this->rewriteHashlinks && self::$options['rewriteHashlinks']) {
 			if(strpos($output, '<base') !== false) {
 				if(SSViewer::$options['rewriteHashlinks'] === 'php') { 
-					$thisURLRelativeToBase = "<?php echo \$_SERVER['REQUEST_URI']; ?>"; 
+					// Emulate Convert::raw2att() without adding this dependency
+					$thisURLRelativeToBase = "<?php echo str_replace(array('&','\"',\"'\",'<','>'), array('&amp;','&quot;','&#39;','&lt;','&gt;'), \$_SERVER['REQUEST_URI']); ?>"; 
 				} else { 
-					$thisURLRelativeToBase = Director::makeRelative(Director::absoluteURL($_SERVER['REQUEST_URI'])); 
+					$thisURLRelativeToBase = Convert::raw2att($_SERVER['REQUEST_URI']); 
 				}
 				$output = preg_replace('/(<a[^>]+href *= *)"#/i', '\\1"' . $thisURLRelativeToBase . '#', $output);
 			}
```
