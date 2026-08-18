# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4610_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4610_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 3-46 of the vulnerable file.

// Released under the MIT License

var util = require("util");
var events = require("events");

exports.create = function create(members) {
	// create new class using php-style syntax (sort of)
	if (!members) members = {};
	
	// setup constructor
	var constructor = null;
	
	// inherit from parent class
	if (members.__parent) {
		if (members.__construct) {
			// explicit constructor passed in
			constructor = members.__construct;
		}
		else {
			// inherit parent's constructor
			var code = members.__parent.toString();
			var args = code.substring( code.indexOf("(")+1, code.indexOf(")") );
			var inner_code = code.substring( code.indexOf("{")+1, code.lastIndexOf("}") );
			eval('constructor = function ('+args+') {'+inner_code+'};');
		}
		
		// inherit rest of parent members
		util.inherits(constructor, members.__parent);
		delete members.__parent;
	}
	else {
		// create new base class
		constructor = members.__construct || function() {};
	}
	delete members.__construct;
	
	// handle static variables
	if (members.__static) {
		for (var key in members.__static) {
			constructor[key] = members.__static[key];
		}
		delete members.__static;
	}
	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,10 +20,11 @@
 		}
 		else {
 			// inherit parent's constructor
-			var code = members.__parent.toString();
-			var args = code.substring( code.indexOf("(")+1, code.indexOf(")") );
-			var inner_code = code.substring( code.indexOf("{")+1, code.lastIndexOf("}") );
-			eval('constructor = function ('+args+') {'+inner_code+'};');
+			var parent = members.__parent;
+			constructor = function() {
+				var args = Array.prototype.slice.call(arguments);
+				parent.apply( this, args );
+			};
 		}
 		
 		// inherit rest of parent members
```
