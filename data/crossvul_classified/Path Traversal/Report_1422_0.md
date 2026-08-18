# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1422_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1422_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 7370-7412 of the vulnerable file.


/**
 * Continue to process
 * @private
 * @param {Request} req
 * @param {Response} res
 * @param {Object} headers
 * @param {String} protocol [description]
 * @return {Framework}
 */
F.$requestcontinue = function(req, res, headers) {

	if (!req || !res || res.headersSent || res.success)
		return;

	// Validates if this request is the file (static file)
	if (req.isStaticFile) {

		// Stops path travelsation outside of "public" directory
		// A potential security issue
		if (req.uri.pathname.indexOf('./') !== -1) {
			req.$total_status(404);
			return;
		}

		F.stats.request.file++;
		if (F._length_files)
			req.$total_file();
		else
			res.continue();
		return;
	}

	if (!PERF[req.method]) {
		req.$total_status(404);
		return;
	}

	F.stats.request.web++;

	req.body = EMPTYOBJECT;
	req.files = EMPTYARRAY;
	req.buffer_exceeded = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7387,9 +7387,13 @@
 
 		// Stops path travelsation outside of "public" directory
 		// A potential security issue
-		if (req.uri.pathname.indexOf('./') !== -1) {
-			req.$total_status(404);
-			return;
+		for (var i = 0; i < req.uri.pathname.length; i++) {
+			var c = req.uri.pathname[i];
+			var n = req.uri.pathname[i + 1];
+			if ((c === '.' && n === '/') || (c === '%' && n === '2' && req.uri.pathname[i + 2] === 'e')) {
+				req.$total_status(404);
+				return;
+			}
 		}
 
 		F.stats.request.file++;
```
