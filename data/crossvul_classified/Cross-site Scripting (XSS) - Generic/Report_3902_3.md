# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3902_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3902_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 2439-2479 of the vulnerable file.


// //----------- jQuery.fn.load()

	// check if load can be called with only url
	QUnit.test( "jQuery.fn.load( String )", function( assert ) {
		assert.expect( 2 );
		jQuery.ajaxSetup( {
			beforeSend: function() {
				assert.strictEqual( this.type, "GET", "no data means GET request" );
			}
		} );
		jQuery( "#first" ).load( baseURL + "name.html", assert.async() );
	} );

	QUnit.test( "jQuery.fn.load() - 404 error callbacks", function( assert ) {
		assert.expect( 6 );
		var done = assert.async();

		addGlobalEvents( "ajaxStart ajaxStop ajaxSend ajaxComplete ajaxError", assert )();
		jQuery( document ).on( "ajaxStop", done );
		jQuery( "<div/>" ).load( baseURL + "404.txt", function() {
			assert.ok( true, "complete" );
		} );
	} );

	// check if load can be called with url and null data
	QUnit.test( "jQuery.fn.load( String, null )", function( assert ) {
		assert.expect( 2 );
		jQuery.ajaxSetup( {
			beforeSend: function() {
				assert.strictEqual( this.type, "GET", "no data means GET request" );
			}
		} );
		jQuery( "#first" ).load( baseURL + "name.html", null, assert.async() );
	} );

	// check if load can be called with url and undefined data
	QUnit.test( "jQuery.fn.load( String, undefined )", function( assert ) {
		assert.expect( 2 );
		jQuery.ajaxSetup( {
			beforeSend: function() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2456,7 +2456,7 @@
 
 		addGlobalEvents( "ajaxStart ajaxStop ajaxSend ajaxComplete ajaxError", assert )();
 		jQuery( document ).on( "ajaxStop", done );
-		jQuery( "<div/>" ).load( baseURL + "404.txt", function() {
+		jQuery( "<div></div>" ).load( baseURL + "404.txt", function() {
 			assert.ok( true, "complete" );
 		} );
 	} );
@@ -2563,7 +2563,7 @@
 				return "Hello World";
 			}
 		} );
-		jQuery( "<div/>" ).load( url( "name.html" ), function( responseText ) {
+		jQuery( "<div></div>" ).load( url( "name.html" ), function( responseText ) {
 			assert.strictEqual( jQuery( this ).html(), "Hello World", "Test div was filled with filtered data" );
 			assert.strictEqual( responseText, "Hello World", "Test callback receives filtered data" );
 			done();
@@ -2573,7 +2573,7 @@
 	QUnit.test( "jQuery.fn.load( String, Object, Function )", function( assert ) {
 		assert.expect( 2 );
 		var done = assert.async();
-		jQuery( "<div />" ).load( url( "mock.php?action=echoHtml" ), {
+		jQuery( "<div></div>" ).load( url( "mock.php?action=echoHtml" ), {
 			"bar": "ok"
 		}, function() {
 			var $node = jQuery( this );
@@ -2587,7 +2587,7 @@
 		assert.expect( 2 );
 		var done = assert.async();
 
-		jQuery( "<div />" ).load( url( "mock.php?action=echoHtml" ), "foo=3&bar=ok", function() {
+		jQuery( "<div></div>" ).load( url( "mock.php?action=echoHtml" ), "foo=3&bar=ok", function() {
 			var $node = jQuery( this );
 			assert.strictEqual( $node.find( "#method" ).text(), "GET", "Check method" );
 			assert.ok( $node.find( "#query" ).text().match( /foo=3&bar=ok/ ), "Check if a string of data is passed correctly" );
```
