# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3858_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3858_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-40 of the vulnerable file.

module("selector", { teardown: moduleTeardown });

/**
 * This test page is for selector tests that require jQuery in order to do the selection
 */

test("element - jQuery only", function() {
	expect( 7 );

	var fixture = document.getElementById("qunit-fixture");

	deepEqual( jQuery("p", fixture).get(), q("firstp","ap","sndp","en","sap","first"), "Finding elements with a Node context." );
	deepEqual( jQuery("p", "#qunit-fixture").get(), q("firstp","ap","sndp","en","sap","first"), "Finding elements with a selector context." );
	deepEqual( jQuery("p", jQuery("#qunit-fixture")).get(), q("firstp","ap","sndp","en","sap","first"), "Finding elements with a jQuery object context." );
	deepEqual( jQuery("#qunit-fixture").find("p").get(), q("firstp","ap","sndp","en","sap","first"), "Finding elements with a context via .find()." );

	ok( jQuery("#length").length, "<input name=\"length\"> cannot be found under IE, see #945" );
	ok( jQuery("#lengthtest input").length, "<input name=\"length\"> cannot be found under IE, see #945" );

	//#7533
	equal( jQuery("<div id=\"A'B~C.D[E]\"><p>foo</p></div>").find("p").length, 1, "Find where context root is a node and has an ID with CSS3 meta characters" );
});

test("class - jQuery only", function() {
	expect( 4 );

	deepEqual( jQuery(".blog", document.getElementsByTagName("p")).get(), q("mark", "simon"), "Finding elements with a context." );
	deepEqual( jQuery(".blog", "p").get(), q("mark", "simon"), "Finding elements with a context." );
	deepEqual( jQuery(".blog", jQuery("p")).get(), q("mark", "simon"), "Finding elements with a context." );
	deepEqual( jQuery("p").find(".blog").get(), q("mark", "simon"), "Finding elements with a context." );
});

test("attributes - jQuery only", function() {
	expect( 2 );

	t( "Find elements with a tabindex attribute", "[tabindex]", ["listWithTabIndex", "foodWithNegativeTabIndex", "linkWithTabIndex", "linkWithNegativeTabIndex", "linkWithNoHrefWithTabIndex", "linkWithNoHrefWithNegativeTabIndex"] );
	// jQuery #12523
	deepEqual(
		jQuery.find( "[title]", null, null, jQuery("#qunit-fixture a").get().concat( document.createTextNode("") ) ),
		q("google"),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,7 +17,7 @@
 	ok( jQuery("#length").length, "<input name=\"length\"> cannot be found under IE, see #945" );
 	ok( jQuery("#lengthtest input").length, "<input name=\"length\"> cannot be found under IE, see #945" );
 
-	//#7533
+	// #7533
 	equal( jQuery("<div id=\"A'B~C.D[E]\"><p>foo</p></div>").find("p").length, 1, "Find where context root is a node and has an ID with CSS3 meta characters" );
 });
 
@@ -75,6 +75,18 @@
 
 	var $div = jQuery("<div/>");
 	equal( $div.is("div"), true, "Make sure .is('nodeName') works on disconnect nodes." );
+});
+
+test("jQuery only - broken", 1, function() {
+	raises(function() {
+		// Setting context to null here somehow avoids QUnit's window.error handling
+		// making the e & e.message correct
+		// For whatever reason, without this,
+		// Sizzle.error will be called but no error will be seen in oldIE
+		jQuery.call( null, " <div/> " );
+	}, function( e ) {
+		return e.message.indexOf("Syntax error") >= 0;
+	}, "leading space invalid: $(' <div/> ')" );
 });
 
 testIframe("selector/html5_selector", "attributes - jQuery.attr", function( jQuery, window, document ) {
```
