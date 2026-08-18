# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1873_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1873_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 58-98 of the vulnerable file.

			beforeSend: function() {
				assert.ok( true, "beforeSend" );
			},
			success: function() {
				assert.ok( true, "success" );
			},
			complete: function() {
				assert.ok( true, "complete" );
			}
		};
	} );

	ajaxTest( "jQuery.ajax() - success callbacks - (url, options) syntax", 8, function( assert ) {
		return {
			setup: addGlobalEvents( "ajaxStart ajaxStop ajaxSend ajaxComplete ajaxSuccess", assert ),
			create: function( options ) {
				return jQuery.ajax( url( "data/name.html" ), options );
			},
			beforeSend: function() {
				assert.ok( true, "beforeSend" );
			},
			success: function() {
				assert.ok( true, "success" );
			},
			complete: function() {
				assert.ok( true, "complete" );
			}
		};
	} );

	ajaxTest( "jQuery.ajax() - success callbacks (late binding)", 8, function( assert ) {
		return {
			setup: addGlobalEvents( "ajaxStart ajaxStop ajaxSend ajaxComplete ajaxSuccess", assert ),
			url: url( "data/name.html" ),
			beforeSend: function() {
				assert.ok( true, "beforeSend" );
			},
			success: true,
			afterSend: function( request ) {
				request.always( function() {
					assert.ok( true, "complete" );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,6 +75,54 @@
 			},
 			beforeSend: function() {
 				assert.ok( true, "beforeSend" );
+			},
+			success: function() {
+				assert.ok( true, "success" );
+			},
+			complete: function() {
+				assert.ok( true, "complete" );
+			}
+		};
+	} );
+
+	ajaxTest( "jQuery.ajax() - do not execute js (crossOrigin)", 2, function( assert ) {
+		return {
+			create: function( options ) {
+				options.crossDomain = true;
+				return jQuery.ajax( url( "data/script.php?header=ecma" ), options );
+			},
+			success: function() {
+				assert.ok( true, "success" );
+			},
+			complete: function() {
+				assert.ok( true, "complete" );
+			}
+		};
+	} );
+
+	ajaxTest( "jQuery.ajax() - execute js for crossOrigin when dataType option is provided", 3,
+		function( assert ) {
+			return {
+				create: function( options ) {
+					options.crossDomain = true;
+					options.dataType = "script";
+					return jQuery.ajax( url( "data/script.php?header=ecma" ), options );
+				},
+				success: function() {
+					assert.ok( true, "success" );
+				},
+				complete: function() {
+					assert.ok( true, "complete" );
+				}
+			};
+		}
+	);
+
+	ajaxTest( "jQuery.ajax() - do not execute js (crossOrigin)", 2, function( assert ) {
+		return {
+			create: function( options ) {
+				options.crossDomain = true;
+				return jQuery.ajax( url( "data/script.php" ), options );
 			},
 			success: function() {
 				assert.ok( true, "success" );
```
