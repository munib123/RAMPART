# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3750_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3750_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-15 of the vulnerable file.

$(document).ready(function() {
	$('#bookmark_add_submit').click(addBookmark);
});

function addBookmark(event) {
	var url = $('#bookmark_add_url').val();
	var tags = $('#bookmark_add_tags').val();
	$.ajax({
		url: 'ajax/addBookmark.php',
		data: 'url=' + encodeURI(url) + '&tags=' + encodeURI(tags),
		success: function(data){ 
			window.close();
		}
	});
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 	var url = $('#bookmark_add_url').val();
 	var tags = $('#bookmark_add_tags').val();
 	$.ajax({
+		type: 'POST',
 		url: 'ajax/addBookmark.php',
 		data: 'url=' + encodeURI(url) + '&tags=' + encodeURI(tags),
 		success: function(data){ 
```
