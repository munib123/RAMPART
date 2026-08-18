# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3902_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3902_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 19-59 of the vulnerable file.

		type: "POST",
		url: url( "mock.php?action=name" ),
		data: "name=peter",
		success: function( msg ) {
			assert.strictEqual( msg, "pan", "Check for POST" );
			done();
		}
	} );

	jQuery( "#first" ).load( url( "name.html" ), function() {
		assert.ok( /^ERROR/.test( jQuery( "#first" ).text() ),
			"Check if content was injected into the DOM" );
		done();
	} );
} );
}

QUnit.test( "attributes", function( assert ) {
	assert.expect( 6 );

	var a = jQuery( "<a/>" ).appendTo( "#qunit-fixture" ),
		input = jQuery( "<input/>" ).appendTo( "#qunit-fixture" );

	assert.strictEqual( a.attr( "foo", "bar" ).attr( "foo" ), "bar", ".attr getter/setter" );
	assert.strictEqual( a.removeAttr( "foo" ).attr( "foo" ), undefined, ".removeAttr" );
	assert.strictEqual( a.prop( "href", "#5" ).prop( "href" ),
		location.href.replace( /\#.*$/, "" ) + "#5",
		".prop getter/setter" );

	a.addClass( "abc def ghj" ).removeClass( "def ghj" );
	assert.strictEqual( a.hasClass( "abc" ), true, ".(add|remove|has)Class, class present" );
	assert.strictEqual( a.hasClass( "def" ), false, ".(add|remove|has)Class, class missing" );

	assert.strictEqual( input.val( "xyz" ).val(), "xyz", ".val getter/setter" );
} );

if ( jQuery.css ) {
QUnit.test( "css", function( assert ) {
	assert.expect( 1 );

	var div = jQuery( "<div/>" ).appendTo( "#qunit-fixture" );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,7 +36,7 @@
 QUnit.test( "attributes", function( assert ) {
 	assert.expect( 6 );
 
-	var a = jQuery( "<a/>" ).appendTo( "#qunit-fixture" ),
+	var a = jQuery( "<a></a>" ).appendTo( "#qunit-fixture" ),
 		input = jQuery( "<input/>" ).appendTo( "#qunit-fixture" );
 
 	assert.strictEqual( a.attr( "foo", "bar" ).attr( "foo" ), "bar", ".attr getter/setter" );
@@ -56,7 +56,7 @@
 QUnit.test( "css", function( assert ) {
 	assert.expect( 1 );
 
-	var div = jQuery( "<div/>" ).appendTo( "#qunit-fixture" );
+	var div = jQuery( "<div></div>" ).appendTo( "#qunit-fixture" );
 
 	assert.strictEqual( div.css( "width", "50px" ).css( "width" ), "50px", ".css getter/setter" );
 } );
@@ -66,7 +66,7 @@
 QUnit.test( "show/hide", function( assert ) {
 	assert.expect( 2 );
 
-	var div = jQuery( "<div/>" ).appendTo( "#qunit-fixture" );
+	var div = jQuery( "<div></div>" ).appendTo( "#qunit-fixture" );
 
 	div.hide();
 	assert.strictEqual( div.css( "display" ), "none", "div hidden" );
@@ -126,7 +126,7 @@
 QUnit.test( "data", function( assert ) {
 	assert.expect( 4 );
 
-	var elem = jQuery( "<div data-c='d'/>" ).appendTo( "#qunit-fixture" );
+	var elem = jQuery( "<div data-c='d'></div>" ).appendTo( "#qunit-fixture" );
 
 	assert.ok( !jQuery.hasData( elem[ 0 ] ), "jQuery.hasData - false" );
 	assert.strictEqual( elem.data( "a", "b" ).data( "a" ), "b", ".data getter/setter" );
@@ -138,7 +138,7 @@
 	assert.expect( 3 );
 
 	var elem = jQuery(
-		"<div style='margin: 10px; padding: 7px; border: 2px solid black;' /> "
+		"<div style='margin: 10px; padding: 7px; border: 2px solid black;'></div> "
 	).appendTo( "#qunit-fixture" );
 
 	assert.strictEqual( elem.width( 50 ).width(), 50, ".width getter/setter" );
@@ -149,7 +149,7 @@
 QUnit.test( "event", function( assert ) {
 	assert.expect( 1 );
 
-	var elem = jQuery( "<div/>" ).appendTo( "#qunit-fixture" );
+	var elem = jQuery( "<div></div>" ).appendTo( "#qunit-fixture" );
 
 	elem
 		.on( "click", function() {
@@ -168,12 +168,12 @@
 
 	var child,
 		elem1 = jQuery( "<div><span></span></div>" ).appendTo( "#qunit-fixture" ),
-		elem2 = jQuery( "<div/>" ).appendTo( "#qunit-fixture" );
+		elem2 = jQuery( "<div></div>" ).appendTo( "#qunit-fixture" );
 
 	assert.strictEqual( elem1.text( "foo" ).text(), "foo", ".html getter/setter" );
 
 	assert.strictEqual(
-		elem1.html( "<span/>" ).html(),
+		elem1.html( "<span></span>" ).html(),
 		"<span></span>",
 		".html getter/setter"
 	);
@@ -182,8 +182,8 @@
 	assert.strictEqual( elem1.prepend( elem2 )[ 0 ].childNodes[ 0 ], elem2[ 0 ], ".prepend" );
 
 	child = elem1.find( "span" );
-	child.after( "<a/>" );
-	child.before( "<b/>" );
+	child.after( "<a></a>" );
+	child.before( "<b></b>" );
 
 	assert.strictEqual(
 		elem1.html(),
@@ -197,8 +197,8 @@
 QUnit[ /jsdom\//.test( navigator.userAgent ) ? "skip" : "test" ]( "offset", function( assert ) {
 	assert.expect( 3 );
 
-	var parent = jQuery( "<div style='position:fixed;top:20px;'/>" ).appendTo( "#qunit-fixture" ),
-		elem = jQuery( "<div style='position:absolute;top:5px;'/>" ).appendTo( parent );
+	var parent = jQuery( "<div style='position:fixed;top:20px;'></div>" ).appendTo( "#qunit-fixture" ),
+		elem = jQuery( "<div style='position:absolute;top:5px;'></div>" ).appendTo( parent );
 
 	assert.strictEqual( elem.offset().top, 25, ".offset getter" );
 	assert.strictEqual( elem.position().top, 5, ".position getter" );
```
