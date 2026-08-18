# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5548_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5548_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-16 of the vulnerable file.

<?php
/**
 * Twitter widget language file
 */

$english = array(

	'twitter:title' => 'Twitter',
	'twitter:info' => 'Display your latest tweets',
	'twitter:username' => 'Enter your twitter username.',
	'twitter:num' => 'The number of tweets to show.',
	'twitter:visit' => 'visit my twitter',
	'twitter:notset' => 'This Twitter widget is not yet set to go. To display your latest tweets, click on - edit - and fill in your details',		
);
					
add_translation("en", $english);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,13 +4,14 @@
  */
 
 $english = array(
-
 	'twitter:title' => 'Twitter',
 	'twitter:info' => 'Display your latest tweets',
-	'twitter:username' => 'Enter your twitter username.',
-	'twitter:num' => 'The number of tweets to show.',
+	'twitter:username' => 'Your twitter username',
+	'twitter:num' => 'Number of tweets to show*',
 	'twitter:visit' => 'visit my twitter',
-	'twitter:notset' => 'This Twitter widget is not yet set to go. To display your latest tweets, click on - edit - and fill in your details',		
+	'twitter:notset' => 'This widget needs to be configured. To display your latest tweets, click EDIT and fill in your Twitter username.',
+	'twitter:invalid' => 'This widget is configured with an invalid Twitter username. Click EDIT to correct it.',
+	'twitter:apibug' => "*Due to a bug in the Twitter 1.0 API, you may see fewer tweets than you ask for.",
 );
 					
 add_translation("en", $english);
```
