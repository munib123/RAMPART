# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 618_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `618_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-41 of the vulnerable file.

var log4js = require('log4js');
var apiLogger = log4js.getLogger("API");
var clientLogger = log4js.getLogger("client");
var formidable = require('formidable');
var apiHandler = require('../../handler/APIHandler');

//This is for making an api call, collecting all post information and passing it to the apiHandler
var apiCaller = function(req, res, fields) {
  res.header("Content-Type", "application/json; charset=utf-8");

  apiLogger.info("REQUEST, v"+ req.params.version + ":" + req.params.func + ", " + JSON.stringify(fields));

  //wrap the send function so we can log the response
  //note: res._send seems to be already in use, so better use a "unique" name
  res._____send = res.send;
  res.send = function (response) {
    response = JSON.stringify(response);
    apiLogger.info("RESPONSE, " + req.params.func + ", " + response);

    //is this a jsonp call, if yes, add the function call
    if(req.query.jsonp)
      response = req.query.jsonp + "(" + response + ")";

    res._____send(response);
  }

  //call the api handler
  apiHandler.handle(req.params.version, req.params.func, fields, req, res);
}

exports.apiCaller = apiCaller;

exports.expressCreateServer = function (hook_name, args, cb) {
  //This is a api GET call, collect all post informations and pass it to the apiHandler
  args.app.get('/api/:version/:func', function (req, res) {
    apiCaller(req, res, req.query)
  });

  //This is a api POST call, collect all post informations and pass it to the apiHandler
  args.app.post('/api/:version/:func', function(req, res) {
    new formidable.IncomingForm().parse(req, function (err, fields, files) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,7 @@
     apiLogger.info("RESPONSE, " + req.params.func + ", " + response);
 
     //is this a jsonp call, if yes, add the function call
-    if(req.query.jsonp)
+    if(req.query.jsonp && isVarName(response))
       response = req.query.jsonp + "(" + response + ")";
 
     res._____send(response);
```
