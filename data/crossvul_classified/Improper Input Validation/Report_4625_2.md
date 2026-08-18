# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4625_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4625_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 383-423 of the vulnerable file.

	}
	
	// No path string
	if (!internalPath) {
		return;
	}
	
	internalPath = clean(internalPath);
	
	// Path is not a string, throw error
	if (typeof internalPath !== "string") {
		throw new Error("Path argument must be a string");
	}
	
	if (typeof obj !== "object") {
		return;
	}
	
	// Path has no dot-notation, set key/value
	if (isNonCompositePath(internalPath)) {
		obj = decouple(obj, options);
		obj[options.transformKey(unEscape(internalPath))] = val;
		return obj;
	}
	
	const newObj = decouple(obj, options);
	const pathParts = split(internalPath);
	const pathPart = pathParts.shift();
	const transformedPathPart = options.transformKey(pathPart);
	let childPart = newObj[transformedPathPart];
	
	if (typeof childPart !== "object") {
		// Create an object or array on the path
		if (String(parseInt(transformedPathPart, 10)) === transformedPathPart) {
			// This is an array index
			newObj[transformedPathPart] = [];
		} else {
			newObj[transformedPathPart] = {};
		}
		
		objPart = newObj[transformedPathPart];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -400,6 +400,9 @@
 	
 	// Path has no dot-notation, set key/value
 	if (isNonCompositePath(internalPath)) {
+		// Do not allow prototype pollution
+		if (internalPath === "__proto__") return obj;
+
 		obj = decouple(obj, options);
 		obj[options.transformKey(unEscape(internalPath))] = val;
 		return obj;
@@ -409,6 +412,10 @@
 	const pathParts = split(internalPath);
 	const pathPart = pathParts.shift();
 	const transformedPathPart = options.transformKey(pathPart);
+
+	// Do not allow prototype pollution
+	if (transformedPathPart === "__proto__") return obj;
+
 	let childPart = newObj[transformedPathPart];
 	
 	if (typeof childPart !== "object") {
@@ -470,19 +477,27 @@
 	
 	// Path has no dot-notation, set key/value
 	if (isNonCompositePath(internalPath)) {
-		if (newObj.hasOwnProperty(unEscape(internalPath))) {
-			delete newObj[options.transformKey(unEscape(internalPath))];
+		const unescapedPath = unEscape(internalPath);
+
+		// Do not allow prototype pollution
+		if (unescapedPath === "__proto__") return obj;
+
+		if (newObj.hasOwnProperty(unescapedPath)) {
+			delete newObj[options.transformKey(unescapedPath)];
 			return newObj;
 		}
 		
 		tracking.returnOriginal = true;
 		return obj;
 	}
-	
 	
 	const pathParts = split(internalPath);
 	const pathPart = pathParts.shift();
 	const transformedPathPart = options.transformKey(unEscape(pathPart));
+
+	// Do not allow prototype pollution
+	if (transformedPathPart === "__proto__") return obj;
+
 	let childPart = newObj[transformedPathPart];
 	
 	if (!childPart) {
@@ -563,7 +578,9 @@
 	
 	const pathParts = split(path);
 	const part = pathParts.shift();
-	
+
+	if (part === "__proto__") return obj;
+
 	if (pathParts.length) {
 		// Generate the path part in the object if it does not already exist
 		obj[part] = decouple(obj[part], options) || {};
@@ -613,6 +630,8 @@
 	
 	const pathParts = split(path);
 	const part = pathParts.shift();
+
+	if (part === "__proto__") return obj;
 	
 	if (pathParts.length) {
 		// Generate the path part in the object if it does not already exist
```
