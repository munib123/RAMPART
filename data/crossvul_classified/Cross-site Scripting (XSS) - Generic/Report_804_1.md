# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 804_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `804_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1045-1085 of the vulnerable file.

	var result, initial = {

		// This will make "copyIsArray" true
		array: [ 1, 2, 3, 4 ],

		// If "copyIsArray" doesn't get reset to false, the check
		// will evaluate true and enter the array copy block
		// instead of the object copy block. Since the ternary in the
		// "copyIsArray" block will evaluate to false
		// (check if operating on an array with ), this will be
		// replaced by an empty array.
		object: {}
	};

	result = jQuery.extend( true, {}, initial );

	assert.deepEqual( result, initial, "The [result] and [initial] have equal shape and values" );
	assert.ok( !Array.isArray( result.object ), "result.object wasn't paved with an empty array" );
} );

QUnit.test( "jQuery.each(Object,Function)", function( assert ) {
	assert.expect( 23 );

	var i, label, seen, callback;

	seen = {};
	jQuery.each( [ 3, 4, 5 ], function( k, v ) {
		seen[ k ] = v;
	} );
	assert.deepEqual( seen, { "0": 3, "1": 4, "2": 5 }, "Array iteration" );

	seen = {};
	jQuery.each( { name: "name", lang: "lang" }, function( k, v ) {
		seen[ k ] = v;
	} );
	assert.deepEqual( seen, { name: "name", lang: "lang" }, "Object iteration" );

	seen = [];
	jQuery.each( [ 1, 2, 3 ], function( k, v ) {
		seen.push( v );
		if ( k === 1 ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1062,6 +1062,13 @@
 	assert.ok( !Array.isArray( result.object ), "result.object wasn't paved with an empty array" );
 } );
 
+QUnit.test( "jQuery.extend( true, ... ) Object.prototype pollution", function( assert ) {
+	assert.expect( 1 );
+
+	jQuery.extend( true, {}, JSON.parse( "{\"__proto__\": {\"devMode\": true}}" ) );
+	assert.ok( !( "devMode" in {} ), "Object.prototype not polluted" );
+} );
+
 QUnit.test( "jQuery.each(Object,Function)", function( assert ) {
 	assert.expect( 23 );
 
```
