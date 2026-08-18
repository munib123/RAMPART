# CrossVul Fix Pair: Exposure of Resource to Wrong Sphere in javascript
**Pair ID:** 4688_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-668
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4688_1`)

## Vulnerability Information & PoC

## Description
Exposure of Resource to Wrong Sphere - Resources such as files and directories may be inadvertently exposed through mechanisms such as insecure permissions, or when a program accidentally operates on the wrong object.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

const MSG_NOTIFY = { TYPE: 'notify' };
const MSG_ALERT = { TYPE: 'alert' };
const COOKIE_OPTIONS = { security: 'strict', httponly: true };
const ALLOW = ['/api/dependencies/', '/api/pages/preview/', '/api/upload/', '/api/nav/', '/api/files/', '/stats/', '/live/', '/api/widgets/', '/logout/'];
const ADMINURL = '/admin/';

var DDOS = {};
var WS = null;

FUNC.notify = function(value) {
	if (WS) {
		MSG_NOTIFY.type = value instanceof Object ? value.type : value;
		MSG_NOTIFY.message = value instanceof Object ? value.message : '';
		WS.send(MSG_NOTIFY);
	}
};

FUNC.send = function(value) {
	WS && WS.send(value);
};

FUNC.alert = function(user, type, value) {
	if (user && WS) {
		MSG_ALERT.type = type;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 const MSG_NOTIFY = { TYPE: 'notify' };
 const MSG_ALERT = { TYPE: 'alert' };
 const COOKIE_OPTIONS = { security: 'strict', httponly: true };
-const ALLOW = ['/api/dependencies/', '/api/pages/preview/', '/api/upload/', '/api/nav/', '/api/files/', '/stats/', '/live/', '/api/widgets/', '/logout/'];
+const ALLOW = { GET: ['/api/dependencies/', '/api/pages/preview/', '/api/nav/', '/api/files/', '/stats/', '/live/', '/api/widgets/', '/logout/', '/api/parts/'], POST: ['/api/upload/', '/api/parts/'] };
 const ADMINURL = '/admin/';
 
 var DDOS = {};
@@ -110,8 +110,10 @@
 		// Allowed URL
 		if (cancel) {
 
-			for (var i = 0, length = ALLOW.length; i < length; i++) {
-				if (controller.url.indexOf(ALLOW[i]) !== -1) {
+			var allow = ALLOW[controller.req.method];
+
+			for (var i = 0, length = allow.length; i < length; i++) {
+				if (controller.url.indexOf(allow[i]) !== -1) {
 					cancel = false;
 					break;
 				}
```
