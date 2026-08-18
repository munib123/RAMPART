# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1587_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1587_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

(function() {
	"use strict";

	var	Remarkable = require('remarkable'),
		fs = require('fs'),
		path = require('path'),
		url = require('url'),
		async = module.parent.require('async'),
		meta = module.parent.require('./meta'),
		nconf = module.parent.require('nconf'),
		parser,
		Markdown = {
			config: {},

			onLoad: function(params, callback) {
				function render(req, res, next) {
					res.render('admin/plugins/markdown', {
						themes: Markdown.themes
					});
				}

				params.router.get('/admin/plugins/markdown', params.middleware.admin.buildHeader, render);
				params.router.get('/api/admin/plugins/markdown', render);
				params.router.get('/markdown/config', function(req, res) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
 (function() {
 	"use strict";
 
-	var	Remarkable = require('remarkable'),
+	var	MarkdownIt = require('markdown-it'),
 		fs = require('fs'),
 		path = require('path'),
 		url = require('url'),
@@ -67,7 +67,18 @@
 					_self.highlight = _self.config.highlight || true;
 					delete _self.config.highlight;
 
-					parser = new Remarkable(_self.config);
+					parser = new MarkdownIt(_self.config);
+
+					// Override the link validator from MarkdownIt, so you cannot link directly to a data-uri
+					parser.validateLink = function(url) {
+						var BAD_PROTOCOLS    = [ 'vbscript', 'javascript', 'file', 'data' ];
+						var str = url.trim().toLowerCase();
+
+						if (str.indexOf(':') >= 0 && BAD_PROTOCOLS.indexOf(str.split(':')[0]) >= 0) {
+							return false;
+						}
+						return true;
+					}
 				});
 			},
 
```
