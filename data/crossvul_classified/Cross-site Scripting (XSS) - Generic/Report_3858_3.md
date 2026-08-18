# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3858_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3858_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 97-137 of the vulnerable file.

	ok( !jQuery("#radio1").is( jQuery("input:checked") ), "Check for pseudoclass: Expected not checked" );
	ok( jQuery("#foo").is( jQuery("div:has(p)") ), "Check for child: Expected a child 'p' element" );
	ok( !jQuery("#foo").is( jQuery("div:has(ul)") ), "Check for child: Did not expect 'ul' element" );

	// Some raw elements
	ok( jQuery("#form").is( jQuery("form")[0] ), "Check for element: A form is a form" );
	ok( !jQuery("#form").is( jQuery("div")[0] ), "Check for element: A form is not a div" );
	ok( jQuery("#mark").is( jQuery(".blog")[0] ), "Check for class: Expected class 'blog'" );
	ok( !jQuery("#mark").is( jQuery(".link")[0] ), "Check for class: Did not expect class 'link'" );
	ok( jQuery("#simon").is( jQuery(".blog.link")[0] ), "Check for multiple classes: Expected classes 'blog' and 'link'" );
	ok( !jQuery("#simon").is( jQuery(".blogTest")[0] ), "Check for multiple classes: Expected classes 'blog' and 'link', but not 'blogTest'" );
});

test("is() with positional selectors", function() {
	expect(23);

	var html = jQuery(
				"<p id='posp'><a class='firsta' href='#'><em>first</em></a><a class='seconda' href='#'><b>test</b></a><em></em></p>"
			).appendTo( "body" ),
		isit = function(sel, match, expect) {
			equal( jQuery( sel ).is( match ), expect, "jQuery( " + sel + " ).is( " + match + " )" );
		};

	isit( "#posp", "#posp:first", true );
	isit( "#posp", "#posp:eq(2)", false );
	isit( "#posp", "#posp a:first", false );

	isit( "#posp .firsta", "#posp a:first", true );
	isit( "#posp .firsta", "#posp a:last", false );
	isit( "#posp .firsta", "#posp a:even", true );
	isit( "#posp .firsta", "#posp a:odd", false );
	isit( "#posp .firsta", "#posp a:eq(0)", true );
	isit( "#posp .firsta", "#posp a:eq(9)", false );
	isit( "#posp .firsta", "#posp em:eq(0)", false );
	isit( "#posp .firsta", "#posp em:first", false );
	isit( "#posp .firsta", "#posp:first", false );

	isit( "#posp .seconda", "#posp a:first", false );
	isit( "#posp .seconda", "#posp a:last", true );
	isit( "#posp .seconda", "#posp a:gt(0)", true );
	isit( "#posp .seconda", "#posp a:lt(5)", true );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -114,7 +114,7 @@
 				"<p id='posp'><a class='firsta' href='#'><em>first</em></a><a class='seconda' href='#'><b>test</b></a><em></em></p>"
 			).appendTo( "body" ),
 		isit = function(sel, match, expect) {
-			equal( jQuery( sel ).is( match ), expect, "jQuery( " + sel + " ).is( " + match + " )" );
+			equal( jQuery( sel ).is( match ), expect, "jQuery('" + sel + "').is('" + match + "')" );
 		};
 
 	isit( "#posp", "#posp:first", true );
```
