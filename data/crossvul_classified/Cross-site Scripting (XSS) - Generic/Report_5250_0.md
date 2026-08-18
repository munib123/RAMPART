# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 5250_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5250_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 189-229 of the vulnerable file.

	var element = $( "<div></div>" ).dialog( { closeOnEscape: false } );
	ok( true, "closeOnEscape: false" );
	ok( element.dialog( "widget" ).is( ":visible" ) && !element.dialog( "widget" ).is( ":hidden" ), "dialog is open before ESC" );
	element.simulate( "keydown", { keyCode: $.ui.keyCode.ESCAPE } )
		.simulate( "keypress", { keyCode: $.ui.keyCode.ESCAPE } )
		.simulate( "keyup", { keyCode: $.ui.keyCode.ESCAPE } );
	ok( element.dialog( "widget" ).is( ":visible" ) && !element.dialog( "widget" ).is( ":hidden" ), "dialog is open after ESC" );

	element.remove();

	element = $( "<div></div>" ).dialog( { closeOnEscape: true } );
	ok( true, "closeOnEscape: true" );
	ok( element.dialog( "widget" ).is( ":visible" ) && !element.dialog( "widget" ).is( ":hidden" ), "dialog is open before ESC" );
	element.simulate( "keydown", { keyCode: $.ui.keyCode.ESCAPE } )
		.simulate( "keypress", { keyCode: $.ui.keyCode.ESCAPE } )
		.simulate( "keyup", { keyCode: $.ui.keyCode.ESCAPE } );
	ok( element.dialog( "widget" ).is( ":hidden" ) && !element.dialog( "widget" ).is( ":visible" ), "dialog is closed after ESC" );
} );

test( "closeText", function() {
	expect( 3 );

	var element = $( "<div></div>" ).dialog();
		equal( $.trim( element.dialog( "widget" ).find( ".ui-dialog-titlebar-close" ).text() ), "Close",
			"default close text" );
	element.remove();

	element = $( "<div></div>" ).dialog( { closeText: "foo" } );
		equal( $.trim( element.dialog( "widget" ).find( ".ui-dialog-titlebar-close" ).text() ), "foo",
			"closeText on init" );
	element.remove();

	element = $( "<div></div>" ).dialog().dialog( "option", "closeText", "bar" );
		equal( $.trim( element.dialog( "widget" ).find( ".ui-dialog-titlebar-close" ).text() ), "bar",
			"closeText via option method" );
	element.remove();
} );

test( "draggable", function() {
	expect( 4 );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,7 +206,7 @@
 } );
 
 test( "closeText", function() {
-	expect( 3 );
+	expect( 4 );
 
 	var element = $( "<div></div>" ).dialog();
 		equal( $.trim( element.dialog( "widget" ).find( ".ui-dialog-titlebar-close" ).text() ), "Close",
@@ -221,6 +221,11 @@
 	element = $( "<div></div>" ).dialog().dialog( "option", "closeText", "bar" );
 		equal( $.trim( element.dialog( "widget" ).find( ".ui-dialog-titlebar-close" ).text() ), "bar",
 			"closeText via option method" );
+	element.remove();
+
+	element = $( "<div></div>" ).dialog( { closeText: "<span>foo</span>" } );
+		equal( $.trim( element.dialog( "widget" ).find( ".ui-dialog-titlebar-close" ).text() ), "<span>foo</span>",
+			"closeText is escaped" );
 	element.remove();
 } );
 
```
