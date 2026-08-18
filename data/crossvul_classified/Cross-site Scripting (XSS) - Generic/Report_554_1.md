# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 554_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `554_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 6-46 of the vulnerable file.

 *
 *     var app = connect()
 *       .use(connect.logger('dev'))
 *       .use(connect.static('public'))
 *       .use(function(req, res){
 *         res.end('hello world\n');
 *       })
 *
 *     http.createServer(app).listen(3000);
 *
 * Installation:
 *
 *     $ npm install connect
 *
 * Middleware:
 *
 *  - [basicAuth](https://github.com/expressjs/basic-auth-connect) basic http authentication
 *  - [cookieParser](https://github.com/expressjs/cookie-parser) cookie parser
 *  - [compress](https://github.com/expressjs/compression) Gzip compression middleware
 *  - [csrf](https://github.com/expressjs/csurf) Cross-site request forgery protection
 *  - [errorHandler](https://github.com/expressjs/errorhandler) flexible error handler
 *  - [favicon](https://github.com/expressjs/favicon) efficient favicon server (with default icon)
 *  - [logger](https://github.com/expressjs/morgan) request logger with custom format support
 *  - [methodOverride](https://github.com/expressjs/method-override) faux HTTP method support
 *  - [responseTime](https://github.com/expressjs/response-time) calculates response-time and exposes via X-Response-Time
 *  - [session](https://github.com/expressjs/session) session management support with bundled MemoryStore
 *  - [timeout](https://github.com/expressjs/timeout) request timeouts
 *  - [vhost](https://github.com/expressjs/vhost) virtual host sub-domain mapping middleware
 *  - [bodyParser](bodyParser.html) extensible request body parser
 *  - [json](json.html) application/json parser
 *  - [urlencoded](urlencoded.html) application/x-www-form-urlencoded parser
 *  - [multipart](multipart.html) multipart/form-data parser
 *  - [cookieSession](cookieSession.html) cookie-based session support
 *  - [staticCache](staticCache.html) memory cache layer for the static() middleware
 *  - [static](static.html) streaming static file server supporting `Range` and more
 *  - [directory](directory.html) directory listing middleware
 *  - [limit](limit.html) limit the bytesize of request bodies
 *  - [query](query.html) automatic querystring parser, populating `req.query`
 *
 * Links:
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,7 @@
  *  - [cookieParser](https://github.com/expressjs/cookie-parser) cookie parser
  *  - [compress](https://github.com/expressjs/compression) Gzip compression middleware
  *  - [csrf](https://github.com/expressjs/csurf) Cross-site request forgery protection
+ *  - [directory](https://github.com/expressjs/serve-index) directory listing middleware
  *  - [errorHandler](https://github.com/expressjs/errorhandler) flexible error handler
  *  - [favicon](https://github.com/expressjs/favicon) efficient favicon server (with default icon)
  *  - [logger](https://github.com/expressjs/morgan) request logger with custom format support
@@ -38,7 +39,6 @@
  *  - [cookieSession](cookieSession.html) cookie-based session support
  *  - [staticCache](staticCache.html) memory cache layer for the static() middleware
  *  - [static](static.html) streaming static file server supporting `Range` and more
- *  - [directory](directory.html) directory listing middleware
  *  - [limit](limit.html) limit the bytesize of request bodies
  *  - [query](query.html) automatic querystring parser, populating `req.query`
  *
```
