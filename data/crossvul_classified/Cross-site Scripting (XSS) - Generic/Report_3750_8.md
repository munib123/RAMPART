# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3750_8
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3750_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-22 of the vulnerable file.

/**
 * Copyright (c) 2012 David Iwanowitsch <david at unclouded dot de>
 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */
$(document).ready(function(){
	OC.search.customResults['Bookm.'] = function(row,item){
		var a=row.find('a');
		a.attr('target','_blank');
		a.click(recordClick);
	}
});

function recordClick(event) {
	var jsFileLocation = $('script[src*=bookmarksearch]').attr('src');
	jsFileLocation = jsFileLocation.replace('js/bookmarksearch.js', '');
	$.ajax({
		url: jsFileLocation + 'ajax/recordClick.php',
		data: 'url=' + encodeURI($(this).attr('href')),
	});	
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,7 @@
 	var jsFileLocation = $('script[src*=bookmarksearch]').attr('src');
 	jsFileLocation = jsFileLocation.replace('js/bookmarksearch.js', '');
 	$.ajax({
+		type: 'POST',
 		url: jsFileLocation + 'ajax/recordClick.php',
 		data: 'url=' + encodeURI($(this).attr('href')),
 	});	
```
