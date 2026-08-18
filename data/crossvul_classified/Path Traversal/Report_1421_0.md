# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1421_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1421_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 51-91 of the vulnerable file.

const REG_ROBOT = /search|agent|bot|crawler|spider/i;
const REG_VERSIONS = /(href|src)="[a-zA-Z0-9/:\-._]+\.(jpg|js|css|png|apng|gif|svg|html|ico|json|less|sass|scss|swf|txt|webp|heif|heic|jpeg|woff|woff2|xls|xlsx|xml|xsl|xslt|zip|rar|csv|doc|docx|eps|gzip|jpe|jpeg|manifest|mov|mp3|flac|mp4|ogg|package|pdf)"/gi;
const REG_COMPILECSS = /url\(.*?\)/g;
const REG_ROUTESTATIC = /^(\/\/|https:|http:)+/;
const REG_NEWIMPL = /^(async\s)?function(\s)?([a-zA-Z$][a-zA-Z0-9$]+)?(\s)?\([a-zA-Z0-9$]+\)|^function anonymous\(\$/;
const REG_RANGE = /bytes=/;
const REG_EMPTY = /\s/g;
const REG_ACCEPTCLEANER = /\s|\./g;
const REG_SANITIZE_BACKSLASH = /\/\//g;
const REG_WEBSOCKET_ERROR = /ECONNRESET|EHOSTUNREACH|EPIPE|is closed/i;
const REG_WINDOWSPATH = /\\/g;
const REG_SCRIPTCONTENT = /<|>|;/;
const REG_HTTPHTTPS = /^(\/)?(http|https):\/\//i;
const REG_NOCOMPRESS = /[.|-]+min(@[a-z0-9]*)?\.(css|js)$/i;
const REG_WWW = /^www\./i;
const REG_TEXTAPPLICATION = /text|application/;
const REG_ENCODINGCLEANER = /[;\s]charset=utf-8/g;
const REG_SKIPERROR = /epipe|invalid\sdistance/i;
const REG_OLDCONF = /-/g;
const REG_UTF8 = /[^\x20-\x7E]+/;
const REG_TRAVEL = /(\/)?\.\.\//g;
const FLAGS_INSTALL = ['get'];
const FLAGS_DOWNLOAD = ['get', 'dnscache'];
const QUERYPARSEROPTIONS = { maxKeys: 33 };
const EMPTYARRAY = [];
const EMPTYOBJECT = {};
const EMPTYREQUEST = { uri: {} };
const SINGLETONS = {};
const REPOSITORY_HEAD = '$head';
const REPOSITORY_META_TITLE = '$title';
const REPOSITORY_META_DESCRIPTION = '$description';
const REPOSITORY_META_KEYWORDS = '$keywords';
const REPOSITORY_META_AUTHOR = '$author';
const REPOSITORY_META_IMAGE = '$image';
const REPOSITORY_PLACE = '$place';
const REPOSITORY_SITEMAP = '$sitemap';
const REPOSITORY_COMPONENTS = '$components';
const ATTR_END = '"';
const ETAG = '858';
const CONCAT = [null, null];
const CLUSTER_CACHE_SET = { TYPE: 'cache-set' };
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -68,7 +68,6 @@
 const REG_SKIPERROR = /epipe|invalid\sdistance/i;
 const REG_OLDCONF = /-/g;
 const REG_UTF8 = /[^\x20-\x7E]+/;
-const REG_TRAVEL = /(\/)?\.\.\//g;
 const FLAGS_INSTALL = ['get'];
 const FLAGS_DOWNLOAD = ['get', 'dnscache'];
 const QUERYPARSEROPTIONS = { maxKeys: 33 };
@@ -7327,7 +7326,19 @@
 	var headers = req.headers;
 	req.$protocol = ((req.connection && req.connection.encrypted) || ((headers['x-forwarded-proto'] || ['x-forwarded-protocol']) === 'https')) ? 'https' : 'http';
 
-	req.url = req.url.replace(REG_TRAVEL, '');
+	var beg = 0;
+
+	// Removes directory browsing
+	for (var i = 0; i < req.url.length; i++) {
+		if (req.url[i] === '.' && req.url[i + 1] === '/')
+			beg = i + 1;
+		else if (req.url[i] === '?')
+			break;
+	}
+
+	if (beg)
+		req.url = req.url.substring(beg);
+
 	req.uri = framework_internal.parseURI(req);
 
 	F.stats.request.request++;
```
