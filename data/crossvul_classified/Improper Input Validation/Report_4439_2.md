# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 4439_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4439_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 62-102 of the vulnerable file.

	    }
	}
	function getNonEmptyPropName(current, descriptor) {
	    var name = getPropName(current, descriptor);
	    return name !== undefined ? name : 'undefined';
	}
	function getPropNames(current, descriptor) {
	    var names = descriptor.names, getNames = descriptor.getNames;
	    if (names !== undefined) {
	        return isArray(names) ? names : [names];
	    }
	    if (getNames) {
	        var gotNames = getNames.call(current, current);
	        if (gotNames !== undefined) {
	            return isArray(gotNames) ? gotNames : [gotNames];
	        }
	    }
	    return getOwnEnumerablePropKeys(current);
	}

	function generate(target, hierarchies, forceOverride) {
	    var current = target;
	    hierarchies.forEach(function (info) {
	        var descriptor = normalizeDescriptor(info);
	        var value = descriptor.value, type = descriptor.type, create = descriptor.create, override = descriptor.override, created = descriptor.created, skipped = descriptor.skipped, got = descriptor.got;
	        var name = getNonEmptyPropName(current, descriptor);
	        if (forceOverride || override || !current[name] || typeof current[name] !== 'object') {
	            var obj = value ? value :
	                type ? new type() :
	                    create ? create.call(current, current, name) :
	                        {};
	            current[name] = obj;
	            if (created) {
	                created.call(current, current, name, obj);
	            }
	        }
	        else {
	            if (skipped) {
	                skipped.call(current, current, name, current[name]);
	            }
	        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,13 +79,18 @@
 	    return getOwnEnumerablePropKeys(current);
 	}
 
+	var propProto = '__proto__';
 	function generate(target, hierarchies, forceOverride) {
 	    var current = target;
 	    hierarchies.forEach(function (info) {
 	        var descriptor = normalizeDescriptor(info);
 	        var value = descriptor.value, type = descriptor.type, create = descriptor.create, override = descriptor.override, created = descriptor.created, skipped = descriptor.skipped, got = descriptor.got;
 	        var name = getNonEmptyPropName(current, descriptor);
-	        if (forceOverride || override || !current[name] || typeof current[name] !== 'object') {
+	        if (forceOverride ||
+	            override ||
+	            !current[name] ||
+	            typeof current[name] !== 'object' ||
+	            (name === propProto && current[name] === Object.prototype)) {
 	            var obj = value ? value :
 	                type ? new type() :
 	                    create ? create.call(current, current, name) :
```
