# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4438_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4438_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 24-64 of the vulnerable file.

		var result = clone(obj1);
		if(Array.isArray(obj1) && Array.isArray(obj2)){
			obj2.forEach(function(item){
				if(result.indexOf(item) == -1) result.push(item);
			});
		} else if(Array.isArray(obj1)){
			//Switch result source - always do the object over the array
			result = clone(obj2);
			obj1.forEach(function(item){
				//Does it exist? If so, iterate and merge first
				if(result[item]) iterateAndMerge(result[item], item);
				else result[item] = true;
			});
		} else if(Array.isArray(obj2)){
			obj2.forEach(function(item){
				//Does it exist? If so, iterate and merge first
				if(result[item]) iterateAndMerge(result[item], item);
				else result[item] = true;
			});
		} else {
			for(var attr in obj2){
				if(!result[attr]){
					result[attr] = clone(obj2[attr]);
				} else if(typeof result[attr] == 'object' && typeof obj2[attr] == 'object'){
					result[attr] = iterateAndMerge(obj1[attr], obj2[attr]);
				} else if(onConflict){
					result[attr] = onConflict(obj1[attr], obj2[attr], attr);
				} else {
					result[attr] = clone(obj2[attr]);
				}
			}
		}
		
		return result;
	};
	
	toMerge.forEach(function(next){
		results = iterateAndMerge(results, next);
	});
	
	return results;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,7 +41,12 @@
 				else result[item] = true;
 			});
 		} else {
+			allowedAttrs = Object.getOwnPropertyNames(obj2)
 			for(var attr in obj2){
+				//This is a safety check to prevent attr being specified as __proto__ or non object types
+				if(!allowedAttrs.includes(attr)){
+					continue
+				}
 				if(!result[attr]){
 					result[attr] = clone(obj2[attr]);
 				} else if(typeof result[attr] == 'object' && typeof obj2[attr] == 'object'){
```
