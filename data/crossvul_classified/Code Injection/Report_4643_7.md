# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4643_7
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4643_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1-41 of the vulnerable file.

'use strict';

const Mailer = require('./mailer');
const shared = require('./shared');
const SMTPPool = require('./smtp-pool');
const SMTPTransport = require('./smtp-transport');
const SendmailTransport = require('./sendmail-transport');
const StreamTransport = require('./stream-transport');
const JSONTransport = require('./json-transport');
const SESTransport = require('./ses-transport');
const fetch = require('./fetch');
const packageData = require('../package.json');

const ETHEREAL_API = (process.env.ETHEREAL_API || 'https://api.nodemailer.com').replace(/\/+$/, '');
const ETHEREAL_WEB = (process.env.ETHEREAL_WEB || 'https://ethereal.email').replace(/\/+$/, '');
const ETHEREAL_CACHE = ['true', 'yes', 'y', '1'].includes(
    (process.env.ETHEREAL_CACHE || 'yes')
        .toString()
        .trim()
        .toLowerCase()
);

let testAccount = false;

module.exports.createTransport = function(transporter, defaults) {
    let urlConfig;
    let options;
    let mailer;

    if (
        // provided transporter is a configuration object, not transporter plugin
        (typeof transporter === 'object' && typeof transporter.send !== 'function') ||
        // provided transporter looks like a connection url
        (typeof transporter === 'string' && /^(smtps?|direct):/i.test(transporter))
    ) {
        if ((urlConfig = typeof transporter === 'string' ? transporter : transporter.url)) {
            // parse a configuration URL into configuration options
            options = shared.parseConnectionUrl(urlConfig);
        } else {
            options = transporter;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,16 +13,11 @@
 
 const ETHEREAL_API = (process.env.ETHEREAL_API || 'https://api.nodemailer.com').replace(/\/+$/, '');
 const ETHEREAL_WEB = (process.env.ETHEREAL_WEB || 'https://ethereal.email').replace(/\/+$/, '');
-const ETHEREAL_CACHE = ['true', 'yes', 'y', '1'].includes(
-    (process.env.ETHEREAL_CACHE || 'yes')
-        .toString()
-        .trim()
-        .toLowerCase()
-);
+const ETHEREAL_CACHE = ['true', 'yes', 'y', '1'].includes((process.env.ETHEREAL_CACHE || 'yes').toString().trim().toLowerCase());
 
 let testAccount = false;
 
-module.exports.createTransport = function(transporter, defaults) {
+module.exports.createTransport = function (transporter, defaults) {
     let urlConfig;
     let options;
     let mailer;
@@ -60,7 +55,7 @@
     return mailer;
 };
 
-module.exports.createTestAccount = function(apiUrl, callback) {
+module.exports.createTestAccount = function (apiUrl, callback) {
     let promise;
 
     if (!callback && typeof apiUrl === 'function') {
@@ -128,7 +123,7 @@
     return promise;
 };
 
-module.exports.getTestMessageUrl = function(info) {
+module.exports.getTestMessageUrl = function (info) {
     if (!info || !info.response) {
         return false;
     }
```
