# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 563_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `563_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 1-26 of the vulnerable file.

var fs = require('fs');

// don't let users crawl up the folder structure by using a/../../../c/d
var cleanUrl = function(url) { 
	url = decodeURIComponent(url);
	while(url.indexOf('..').length > 0) { url = url.replace('..', ''); }
	return url;
};

/*  
example usage:
	require('http').createServer(function (req, res) {
		server.handleRequest(port, path, req, res, vpath);
	}).listen(port);
*/
exports.handleRequest = function(vpath, path, req, res, readOnly, logHeadRequests) {	
	// vpath: (optional) virtual path to host in the url
	// path: the file system path to serve
	// readOnly: whether to allow modifications to the file

	// our error handler
	var writeError = function (err, code) { 
		code = code || 500;
		console.log('Error ' + code + ': ' + err);
		// write the error to the response, if possible
		try {			
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
 // don't let users crawl up the folder structure by using a/../../../c/d
 var cleanUrl = function(url) { 
 	url = decodeURIComponent(url);
-	while(url.indexOf('..').length > 0) { url = url.replace('..', ''); }
+	while(url.indexOf('..') >= 0) { url = url.replace('..', ''); }
 	return url;
 };
 
```
