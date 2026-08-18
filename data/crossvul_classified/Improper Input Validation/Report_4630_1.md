# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4630_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4630_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 167-207 of the vulnerable file.

 *
 * @function set
 * @param {object} root The root of the namespace, bMoor.namespace.root if not defined
 * @param {string|array} space The namespace
 * @param {*} value The value to set the namespace to
 * @return {*}
 **/
function set( root, space, value ){
	var i, c, 
		val,
		nextSpace,
		curSpace = root;
	
	space = parse(space);

	val = space.pop();

	for( i = 0, c = space.length; i < c; i++ ){
		nextSpace = space[ i ];
			
		if ( isUndefined(curSpace[nextSpace]) ){
			curSpace[ nextSpace ] = {};
		}
			
		curSpace = curSpace[ nextSpace ];
	}

	curSpace[ val ] = value;

	return curSpace;
}

function _makeSetter( property, next ){
	if ( next ){
		return function setter( ctx, value ){
			var t = ctx[property];

			if ( !t ){
				t = ctx[property] = {};
			}
			
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -184,6 +184,10 @@
 	for( i = 0, c = space.length; i < c; i++ ){
 		nextSpace = space[ i ];
 			
+		if (nextSpace === '__proto__'){
+			return null;
+		}
+
 		if ( isUndefined(curSpace[nextSpace]) ){
 			curSpace[ nextSpace ] = {};
 		}
@@ -197,6 +201,10 @@
 }
 
 function _makeSetter( property, next ){
+	if (property === '__proto__'){
+		throw new Error('unable to access __proto__');
+	}
+
 	if ( next ){
 		return function setter( ctx, value ){
 			var t = ctx[property];
@@ -250,6 +258,10 @@
 		for( i = 0, c = space.length; i < c; i++ ){
 			nextSpace = space[i];
 				
+			if (nextSpace === '__proto__'){
+				return null;
+			}
+
 			if ( isUndefined(curSpace[nextSpace]) ){
 				return;
 			}
@@ -262,6 +274,10 @@
 }
 
 function _makeGetter( property, next ){
+	if (property === '__proto__'){
+		throw new Error('unable to access __proto__');
+	}
+
 	if (next){
 		return function getter( obj ){
 			try {
```
