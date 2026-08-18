# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4556_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4556_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 438-478 of the vulnerable file.

		});
		return this;
	}
	
	function jqMix(obj, props){
		// summary:
		//		an attempt at a mixin that follows
		//		jquery's .extend rules. Seems odd. Not sure how
		//		to resolve this with dojo.mixin and what the use
		//		cases are for the jquery version.
		//		Copying some code from dojo._mixin.
		if(obj == props){
			return obj;
		}
		var tobj = {};
		for(var x in props){
			// the "tobj" condition avoid copying properties in "props"
			// inherited from Object.prototype.  For example, if obj has a custom
			// toString() method, don't overwrite it with the toString() method
			// that props inherited from Object.prototype
			if((tobj[x] === undefined || tobj[x] != props[x]) && props[x] !== undefined && obj != props[x]){
				if(dojo.isObject(obj[x]) && dojo.isObject(props[x])){
					if(dojo.isArray(props[x])){
						obj[x] = props[x];
					}else{
						obj[x] = jqMix(obj[x], props[x]);
					}
				}else{
					obj[x] = props[x];
				}
			}
		}
		// IE doesn't recognize custom toStrings in for..in
		if(dojo.isIE && props){
			var p = props.toString;
			if(typeof p == "function" && p != obj.toString && p != tobj.toString &&
				p != "\nfunction toString() {\n    [native code]\n}\n"){
					obj.toString = props.toString;
			}
		}
		return obj; // Object
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -455,7 +455,7 @@
 			// inherited from Object.prototype.  For example, if obj has a custom
 			// toString() method, don't overwrite it with the toString() method
 			// that props inherited from Object.prototype
-			if((tobj[x] === undefined || tobj[x] != props[x]) && props[x] !== undefined && obj != props[x]){
+			if(x !== '__proto__ ' && ((tobj[x] === undefined || tobj[x] != props[x])) && props[x] !== undefined && obj != props[x]){
 				if(dojo.isObject(obj[x]) && dojo.isObject(props[x])){
 					if(dojo.isArray(props[x])){
 						obj[x] = props[x];
```
