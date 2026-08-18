# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3902_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3902_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 6-46 of the vulnerable file.

		this.sandbox.restore();
		return moduleTeardown.apply( this, arguments );
	}
} );

QUnit.test( "Basic requirements", function( assert ) {
	assert.expect( 7 );
	assert.ok( Array.prototype.push, "Array.push()" );
	assert.ok( Function.prototype.apply, "Function.apply()" );
	assert.ok( document.getElementById, "getElementById" );
	assert.ok( document.getElementsByTagName, "getElementsByTagName" );
	assert.ok( RegExp, "RegExp" );
	assert.ok( jQuery, "jQuery" );
	assert.ok( $, "$" );
} );

QUnit.test( "jQuery()", function( assert ) {

	var elem, i,
		obj = jQuery( "div" ),
		code = jQuery( "<code/>" ),
		img = jQuery( "<img/>" ),
		div = jQuery( "<div/><hr/><code/><b/>" ),
		exec = false,
		expected = 23,
		attrObj = {
			"text": "test",
			"class": "test2",
			"id": "test3"
		};

	// The $(html, props) signature can stealth-call any $.fn method, check for a
	// few here but beware of modular builds where these methods may be excluded.
	if ( jQuery.fn.click ) {
		expected++;
		attrObj[ "click" ] = function() { assert.ok( exec, "Click executed." ); };
	}
	if ( jQuery.fn.width ) {
		expected++;
		attrObj[ "width" ] = 10;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,9 +23,9 @@
 
 	var elem, i,
 		obj = jQuery( "div" ),
-		code = jQuery( "<code/>" ),
+		code = jQuery( "<code></code>" ),
 		img = jQuery( "<img/>" ),
-		div = jQuery( "<div/><hr/><code/><b/>" ),
+		div = jQuery( "<div></div><hr/><code></code><b/>" ),
 		exec = false,
 		expected = 23,
 		attrObj = {
@@ -113,7 +113,7 @@
 	elem = jQuery( "\n\n<em>world</em>" )[ 0 ];
 	assert.equal( elem.nodeName.toLowerCase(), "em", "leading newlines" );
 
-	elem = jQuery( "<div/>", attrObj );
+	elem = jQuery( "<div></div>", attrObj );
 
 	if ( jQuery.fn.width ) {
 		assert.equal( elem[ 0 ].style.width, "10px", "jQuery() quick setter width" );
@@ -458,7 +458,7 @@
 
 	assert.ok( jQuery( "<link rel='stylesheet'/>" )[ 0 ], "Creating a link" );
 
-	assert.ok( !jQuery( "<script/>" )[ 0 ].parentNode, "Create a script" );
+	assert.ok( !jQuery( "<script></script>" )[ 0 ].parentNode, "Create a script" );
 
 	assert.ok( jQuery( "<input/>" ).attr( "type", "hidden" ), "Create an input and set the type." );
 
@@ -526,8 +526,8 @@
 QUnit.test( "jQuery('html', context)", function( assert ) {
 	assert.expect( 1 );
 
-	var $div = jQuery( "<div/>" )[ 0 ],
-		$span = jQuery( "<span/>", $div );
+	var $div = jQuery( "<div></div>" )[ 0 ],
+		$span = jQuery( "<span></span>", $div );
 	assert.equal( $span.length, 1, "verify a span created with a div context works, #1763" );
 } );
 
@@ -1356,7 +1356,7 @@
 	assert.equal( jQuery.parseHTML( "text" )[ 0 ].nodeType, 3, "Parsing text returns a text node" );
 	assert.equal( jQuery.parseHTML( "\t<div></div>" )[ 0 ].nodeValue, "\t", "Preserve leading whitespace" );
 
-	assert.equal( jQuery.parseHTML( " <div/> " )[ 0 ].nodeType, 3, "Leading spaces are treated as text nodes (#11290)" );
+	assert.equal( jQuery.parseHTML( " <div></div> " )[ 0 ].nodeType, 3, "Leading spaces are treated as text nodes (#11290)" );
 
 	html = jQuery.parseHTML( "<div>test div</div>" );
 
```
