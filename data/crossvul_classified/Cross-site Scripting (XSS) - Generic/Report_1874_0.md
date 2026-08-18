# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1874_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1874_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 204-244 of the vulnerable file.


	current = dataTypes.shift();

	// Convert to each sequential dataType
	while ( current ) {

		if ( s.responseFields[ current ] ) {
			jqXHR[ s.responseFields[ current ] ] = response;
		}

		// Apply the dataFilter if provided
		if ( !prev && isSuccess && s.dataFilter ) {
			response = s.dataFilter( response, s.dataType );
		}

		prev = current;
		current = dataTypes.shift();

		if ( current ) {

		// There's only work to do if current dataType is non-auto
			if ( current === "*" ) {

				current = prev;

			// Convert response if prev dataType is non-auto and differs from current
			} else if ( prev !== "*" && prev !== current ) {

				// Seek a direct converter
				conv = converters[ prev + " " + current ] || converters[ "* " + current ];

				// If none found, seek a pair
				if ( !conv ) {
					for ( conv2 in converters ) {

						// If conv2 outputs current
						tmp = conv2.split( " " );
						if ( tmp[ 1 ] === current ) {

							// If prev can be converted to accepted input
							conv = converters[ prev + " " + tmp[ 0 ] ] ||
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -221,13 +221,18 @@
 
 		if ( current ) {
 
-		// There's only work to do if current dataType is non-auto
+			// There's only work to do if current dataType is non-auto
 			if ( current === "*" ) {
 
 				current = prev;
 
 			// Convert response if prev dataType is non-auto and differs from current
 			} else if ( prev !== "*" && prev !== current ) {
+
+				// Mitigate possible XSS vulnerability (gh-2432)
+				if ( s.crossDomain && current === "script" ) {
+					continue;
+				}
 
 				// Seek a direct converter
 				conv = converters[ prev + " " + current ] || converters[ "* " + current ];
```
