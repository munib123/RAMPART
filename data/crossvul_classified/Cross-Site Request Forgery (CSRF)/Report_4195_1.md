# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 4195_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4195_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 1-28 of the vulnerable file.

require('../lib/initConf');
require('../lib/setupProxy');

var unzipper = require('unzipper');
var path = require('path');
var archiver = require('archiver');
var cas = require('../lib/add_certs');
var os = require('os');
var fs = require('fs');
var http = require('http');
var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session')
var logger = require('morgan');
var xtend = require('xtend');
var request = require('request');
var urlJoin = require('url-join');
var exec = require('child_process').exec;
var app = express();
var freeport = require('freeport');
var multipart = require('connect-multiparty');
var test_config = require('./test_config');
var Users = require('../lib/users');

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public'));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 var path = require('path');
 var archiver = require('archiver');
 var cas = require('../lib/add_certs');
+var csrf = require('csurf');
 var os = require('os');
 var fs = require('fs');
 var http = require('http');
@@ -31,7 +32,7 @@
 app.use(session({
   secret: 'sojo sut ed oterces le'
 }));
-
+var csrfProtection = csrf({ cookie: true });
 var detected_settings = {};
 
 if (process.platform === 'win32') {
@@ -113,18 +114,20 @@
   });
 }
 
-app.get('/', set_current_config, function(req, res) {
+app.get('/', set_current_config, csrfProtection, function(req, res) {
   console.log(req.session.LDAP_RESULTS);
   res.render('index', xtend(req.current_config, {
     SUCCESS: req.query && req.query.s === '1',
     LDAP_RESULTS: req.session.LDAP_RESULTS
   }, {
     detected: detected_settings
+  }, {
+    csrfToken: req.csrfToken()
   }));
   delete req.session.LDAP_RESULTS;
 });
 
-app.post('/ldap', set_current_config, function(req, res, next) {
+app.post('/ldap', set_current_config, csrfProtection, function(req, res, next) {
   // Convert ENABLE_WRITE_BACK and ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD to boolean.
   req.body.ENABLE_WRITE_BACK = !!(req.body.ENABLE_WRITE_BACK && req.body.ENABLE_WRITE_BACK === 'on');
   req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD = !!(req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD && req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD === 'on');
@@ -149,7 +152,7 @@
   });
 }, merge_config);
 
-app.post('/server', multipart(), set_current_config, function(req, res, next) {
+app.post('/server', multipart(), set_current_config, csrfProtection, function(req, res, next) {
   if (req.body.PORT || req.current_config.PORT) return next();
   freeport(function(er, port) {
     req.body.PORT = port;
@@ -165,7 +168,7 @@
   });
 }, merge_config);
 
-app.post('/ticket', set_current_config, function(req, res, next) {
+app.post('/ticket', set_current_config, csrfProtection, function(req, res, next) {
   if (!req.body.PROVISIONING_TICKET) {
     return res.render('index', xtend(req.current_config, {
       ERROR: 'The ticket url ' + req.body.PROVISIONING_TICKET + ' is not vaild.'
@@ -257,7 +260,7 @@
   archive.finalize();
 });
 
-app.post('/import', set_current_config, multipart(), function(req, res, next) {
+app.post('/import', set_current_config, csrfProtection, multipart(), function(req, res, next) {
   console.log('Importing configuration.');
 
   if (!req.files || !req.files.IMPORT_FILE || req.files.IMPORT_FILE.size === 0) {
@@ -312,7 +315,7 @@
   });
 });
 
-app.post('/logs/clear', function(req, res) {
+app.post('/logs/clear', csrfProtection, function(req, res) {
   fs.writeFile(__dirname + '/../logs.log', '', function(err) {
     if (err) {
       res.status(500);
@@ -349,7 +352,7 @@
   });
 });
 
-app.post('/profile-mapper', function(req, res) {
+app.post('/profile-mapper', csrfProtection, function(req, res) {
   fs.writeFile(__dirname + '/../lib/profileMapper.js', req.body.code, function(err) {
     if (err) {
       res.status(500);
@@ -440,7 +443,7 @@
     archive.finalize();
   });
 
-app.post('/updater/run', set_current_config, function(req, res) {
+app.post('/updater/run', csrfProtection, set_current_config, function(req, res) {
   run(__dirname + '/../update-connector.cmd', [], function(data) {
     res.writeHead(200, {
       "Content-Type": "text/plain"
```
