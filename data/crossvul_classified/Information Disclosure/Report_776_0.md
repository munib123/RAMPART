# CrossVul Fix Pair: Exposure of Resource to Wrong Sphere in javascript
**Pair ID:** 776_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-668
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `776_0`)

## Vulnerability Information & PoC

## Description
Exposure of Resource to Wrong Sphere - Resources such as files and directories may be inadvertently exposed through mechanisms such as insecure permissions, or when a program accidentally operates on the wrong object.

## Vulnerable Code
```javascript
Lines 63-103 of the vulnerable file.

			if (!_typeIs.array(fields)) {
				fields = [fields];
			}
			fields.forEach(function (field) {
				delete this.custom[field];
			}, this);
		};
	}

	// Inspection class (Base class) ---------------------------------------------
	// Use to extend Validation and Sanitization prototypes. Inspection
	// constructor shall be called in derived class constructor.

	function Inspection(schema, custom) {
		var _stack = ['@'];

		this._schema = schema;
		this._custom = {};
		if (custom != null) {
			for (var key in custom) {
				if (custom.hasOwnProperty(key)){
					this._custom['$' + key] = custom[key];
				}
			}
		}

		this._getDepth = function () {
			return _stack.length;
		};

		this._dumpStack = function () {
			return _stack.map(function (i) {return i.replace(/^\[/g, '\u001b\u001c\u001d\u001e');})
			.join('.').replace(/\.\u001b\u001c\u001d\u001e/g, '[');
		};

		this._deeperObject = function (name) {
			_stack.push((/^[a-z$_][a-z0-9$_]*$/i).test(name) ? name : '["' + name + '"]');
			return this;
		};

		this._deeperArray = function (i) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,7 +80,7 @@
 		this._custom = {};
 		if (custom != null) {
 			for (var key in custom) {
-				if (custom.hasOwnProperty(key)){
+				if (Object.prototype.hasOwnProperty.call(custom, key)) {
 					this._custom['$' + key] = custom[key];
 				}
 			}
@@ -480,7 +480,7 @@
 			}
 			else {
 				for (var key in candidate) {
-					if (candidate.hasOwnProperty(key)){
+					if (Object.prototype.hasOwnProperty.call(candidate, key)) {
 						this._deeperArray(key);
 						this._validate(items, candidate[key]);
 						this._back();
@@ -1011,7 +1011,7 @@
 			}
 			else {
 				for (i in post) {
-					if(post.hasOwnProperty(i)){
+					if (Object.prototype.hasOwnProperty.call(post, i)) {
 						this._deeperArray(i);
 						post[i] = this._sanitize(schema.items, post[i]);
 						this._back();
@@ -1430,7 +1430,7 @@
 			var prop = schema.properties || {};
 
 			for (var key in prop) {
-				if (prop.hasOwnProperty(key)){
+				if (Object.prototype.hasOwnProperty.call(prop, key)) {
 					if (prop[key].optional === true && _rand.bool() === true) {
 						continue;
 					}
```
