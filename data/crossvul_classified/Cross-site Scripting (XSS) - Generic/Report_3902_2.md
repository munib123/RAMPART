# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 3902_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3902_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 32-72 of the vulnerable file.

	<ul>
		<li>
			Success:
			<span id="success">
			</span>
		</li>
		<li>
			Error:
			<span id="error">
			</span>
		</li>
	</ul>
	<h2>
		Logs:
	</h2>
	<ul id="log">
	</ul>
	<script>
		var logUL = jQuery( "#log" );
		function doLog( message, args ) {
			jQuery( "<li />").appendTo( logUL ).text( message + ': "' + Array.prototype.join.call( args, '" - "' ) + '"' );
		}
		jQuery.ajax( "./data/badjson.js" , {
			context: jQuery( "#success" ),
			dataType: "text"
		}).success(function( data, _, xhr ) {
			doLog( "Success (" + xhr.status + ")" , arguments );
			this.addClass( data ? "success" : "error" ).text( "OK" );
		}).error(function( xhr ) {
			doLog( "Success (" + xhr.status + ")" , arguments );
			this.addClass( "error" ).text( "FAIL" );
		});
		jQuery.ajax( "./data/doesnotexist.ext" , {
			context: jQuery( "#error" ),
			dataType: "text"
		}).error(function( xhr ) {
			doLog( "Error (" + xhr.status + ")" , arguments );
			this.addClass( "success" ).text( "OK" );
		}).success(function( data, _, xhr ) {
			doLog( "Error (" + xhr.status + ")" , arguments );
			this.addClass( "error" ).text( "FAIL" );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,7 @@
 	<script>
 		var logUL = jQuery( "#log" );
 		function doLog( message, args ) {
-			jQuery( "<li />").appendTo( logUL ).text( message + ': "' + Array.prototype.join.call( args, '" - "' ) + '"' );
+			jQuery( "<li></li>" ).appendTo( logUL ).text( message + ': "' + Array.prototype.join.call( args, '" - "' ) + '"' );
 		}
 		jQuery.ajax( "./data/badjson.js" , {
 			context: jQuery( "#success" ),
```
