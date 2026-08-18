# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3851_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3851_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-37 of the vulnerable file.

(function( $ ) {

module( "tooltip: options" );

test( "disabled: true", function() {
	expect( 1 );
	$( "#tooltipped1" ).tooltip({
		disabled: true
	}).tooltip( "open" );
	equal( $( ".ui-tooltip" ).length, 0 );
});

test( "content: default", function() {
	expect( 1 );
	var element = $( "#tooltipped1" ).tooltip().tooltip( "open" );
	deepEqual( $( "#" + element.data( "ui-tooltip-id" ) ).text(), "anchortitle" );
});

test( "content: return string", function() {
	expect( 1 );
	var element = $( "#tooltipped1" ).tooltip({
		content: function() {
			return "customstring";
		}
	}).tooltip( "open" );
	deepEqual( $( "#" + element.data( "ui-tooltip-id" ) ).text(), "customstring" );
});

test( "content: return jQuery", function() {
	expect( 1 );
	var element = $( "#tooltipped1" ).tooltip({
		content: function() {
			return $( "<div>" ).html( "cu<b>s</b>tomstring" );
		}
	}).tooltip( "open" );
	deepEqual( $( "#" + element.data( "ui-tooltip-id" ) ).text(), "customstring" );
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,20 @@
 	expect( 1 );
 	var element = $( "#tooltipped1" ).tooltip().tooltip( "open" );
 	deepEqual( $( "#" + element.data( "ui-tooltip-id" ) ).text(), "anchortitle" );
+});
+
+test( "content: default; HTML escaping", function() {
+	expect( 2 );
+	var scriptText = "<script>$.ui.tooltip.hacked = true;</script>",
+		element = $( "#tooltipped1" );
+
+	$.ui.tooltip.hacked = false;
+	element.attr( "title", scriptText )
+		.tooltip()
+		.tooltip( "open" );
+	equal( $.ui.tooltip.hacked, false, "script did not execute" );
+	deepEqual( $( "#" + element.data( "ui-tooltip-id" ) ).text(), scriptText,
+		"correct tooltip text" );
 });
 
 test( "content: return string", function() {
```
