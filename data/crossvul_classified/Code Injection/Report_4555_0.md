# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4555_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4555_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 27-67 of the vulnerable file.

		return value.nodeType === 1;
	}

	function isFormData(value) {
		return has('native-formdata') && value instanceof FormData;
	}

	function shouldDeepCopy(value) {
		return value &&
			typeof value === 'object' &&
			!isFormData(value) &&
			!isElement(value) &&
			!isBlob(value) &&
			!isArrayBuffer(value)
	}

	exports.deepCopy = function(target, source) {
		for (var name in source) {
			var tval = target[name],
  			    sval = source[name];
			if (tval !== sval) {
				if (shouldDeepCopy(sval)) {
					if (Object.prototype.toString.call(sval) === '[object Date]') { // use this date test to handle crossing frame boundaries
						target[name] = new Date(sval);
					} else if (lang.isArray(sval)) {
 						  target[name] = exports.deepCopyArray(sval);
					} else {
						if (tval && typeof tval === 'object') {
							exports.deepCopy(tval, sval);
						} else {
							target[name] = exports.deepCopy({}, sval);
						}
					}
				} else {
					target[name] = sval;
				}
			}
		}
		return target;
	};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,7 +44,7 @@
 		for (var name in source) {
 			var tval = target[name],
   			    sval = source[name];
-			if (tval !== sval) {
+			if (name !== '__proto__' && tval !== sval) {
 				if (shouldDeepCopy(sval)) {
 					if (Object.prototype.toString.call(sval) === '[object Date]') { // use this date test to handle crossing frame boundaries
 						target[name] = new Date(sval);
```
