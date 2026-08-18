# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3858_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3858_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 10-50 of the vulnerable file.

	expect(7);
	ok( Array.prototype.push, "Array.push()" );
	ok( Function.prototype.apply, "Function.apply()" );
	ok( document.getElementById, "getElementById" );
	ok( document.getElementsByTagName, "getElementsByTagName" );
	ok( RegExp, "RegExp" );
	ok( jQuery, "jQuery" );
	ok( $, "$" );
});

test("jQuery()", function() {

	var elem, i,
		obj = jQuery("div"),
		main = jQuery("#qunit-fixture"),
		code = jQuery("<code/>"),
		img = jQuery("<img/>"),
		div = jQuery("<div/><hr/><code/><b/>"),
		exec = false,
		lng = "",
		expected = 26,
		attrObj = {
			"click": function() { ok( exec, "Click executed." ); },
			"text": "test",
			"class": "test2",
			"id": "test3"
		};

	// The $(html, props) signature can stealth-call any $.fn method, check for a
	// few here but beware of modular builds where these methods may be excluded.
	if ( jQuery.fn.width ) {
		expected++;
		attrObj["width"] = 10;
	}
	if ( jQuery.fn.offset ) {
		expected++;
		attrObj["offset"] = { "top": 1, "left": 1 };
	}
	if ( jQuery.fn.css ) {
		expected += 2;
		attrObj["css"] = { "paddingLeft": 1, "paddingRight": 1 };
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 		div = jQuery("<div/><hr/><code/><b/>"),
 		exec = false,
 		lng = "",
-		expected = 26,
+		expected = 22,
 		attrObj = {
 			"click": function() { ok( exec, "Click executed." ); },
 			"text": "test",
@@ -139,15 +139,9 @@
 	// manually clean up detached elements
 	elem.remove();
 
-	equal( jQuery(" <div/> ").length, 1, "Make sure whitespace is trimmed." );
-	equal( jQuery(" a<div/>b ").length, 1, "Make sure whitespace and other characters are trimmed." );
-
 	for ( i = 0; i < 128; i++ ) {
 		lng += "12345678";
 	}
-
-	equal( jQuery(" <div>" + lng + "</div> ").length, 1, "Make sure whitespace is trimmed on long strings." );
-	equal( jQuery(" a<div>" + lng + "</div>b ").length, 1, "Make sure whitespace and other characters are trimmed on long strings." );
 });
 
 test( "selector state", function() {
@@ -1206,7 +1200,7 @@
 });
 
 test("jQuery.parseHTML", function() {
-	expect( 12 );
+	expect( 13 );
 
 	var html, nodes;
 
@@ -1231,6 +1225,8 @@
 
 	equal( jQuery.parseHTML("text")[0].nodeType, 3, "Parsing text returns a text node" );
 	equal( jQuery.parseHTML( "\t<div></div>" )[0].nodeValue, "\t", "Preserve leading whitespace" );
+
+	equal( jQuery.parseHTML(" <div/> ")[0].nodeType, 3, "Leading spaces are treated as text nodes (#11290)" );
 });
 
 test("jQuery.parseJSON", function(){
```
