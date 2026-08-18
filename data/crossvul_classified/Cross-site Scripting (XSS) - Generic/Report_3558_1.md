# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3558_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3558_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 448-488 of the vulnerable file.

	ok( !jQuery.isXMLDoc( document.documentElement ), "HTML documentElement" );
	ok( !jQuery.isXMLDoc( document.body ), "HTML Body Element" );

	var iframe = document.createElement("iframe");
	document.body.appendChild( iframe );

	try {
		var body = jQuery(iframe).contents()[0];

		try {
			ok( !jQuery.isXMLDoc( body ), "Iframe body element" );
		} catch(e) {
			ok( false, "Iframe body element exception" );
		}

	} catch(e) {
		ok( true, "Iframe body element - iframe not working correctly" );
	}

	document.body.removeChild( iframe );
});

if ( !isLocal ) {
test("isXMLDoc - XML", function() {
	expect(3);
	stop();
	jQuery.get("data/dashboard.xml", function(xml) {
		ok( jQuery.isXMLDoc( xml ), "XML document" );
		ok( jQuery.isXMLDoc( xml.documentElement ), "XML documentElement" );
		ok( jQuery.isXMLDoc( jQuery("tab", xml)[0] ), "XML Tab Element" );
		start();
	});
});
}

test("isWindow", function() {
	expect( 12 );

	ok( jQuery.isWindow(window), "window" );
	ok( !jQuery.isWindow(), "empty" );
	ok( !jQuery.isWindow(null), "null" );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -465,6 +465,24 @@
 	}
 
 	document.body.removeChild( iframe );
+});
+
+test("XSS via location.hash", function() {
+	expect(1);
+	
+	stop();
+	jQuery._check9521 = function(x){
+		ok( x, "script called from #id-like selector with inline handler" );
+		jQuery("#check9521").remove();
+		delete jQuery._check9521;
+		start();
+	};
+	try {
+		// This throws an error because it's processed like an id
+		jQuery( '#<img id="check9521" src="no-such-.gif" onerror="jQuery._check9521(false)">' ).appendTo("#qunit-fixture");
+	} catch (err) {
+		jQuery._check9521(true);
+	};
 });
 
 if ( !isLocal ) {
```
