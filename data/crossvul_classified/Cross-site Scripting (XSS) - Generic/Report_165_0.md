# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 165_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `165_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 10-42 of the vulnerable file.

* Any technique supported by the User Agent MAY be used to cause the submission of the form, and any form content 
* necessary to support this MAY be included, such as submit controls and client-side scripting commands. However, 
* the Client MUST be able to process the message without regard for the mechanism by which the form submission was 
* initiated. (http://openid.net/specs/oauth-v2-form-post-response-mode-1_0-01.html)
**/

var input = '<input type="hidden" name="{NAME}" value="{VALUE}"/>';
var html = '<html>' +
  '<head><title>Submit This Form</title></head>' +
  '<body onload="javascript:document.forms[0].submit()">' +
    '<form method="post" action="{ACTION}">' +
      '{INPUTS}' +
    '</form>' +
  '</body>' +
'</html>';

exports = module.exports = function (txn, res, params) {
  var inputs = [];
  
  Object.keys(params).forEach(function (k) {
    inputs.push(input.replace('{NAME}', k).replace('{VALUE}', entities.encode(params[k])));
   });

  res.setHeader('Content-Type', 'text/html;charset=UTF-8');
  res.setHeader('Cache-Control', 'no-cache, no-store');
  res.setHeader('Pragma', 'no-cache');

  return res.end(html.replace('{ACTION}', entities.encode(txn.redirectURI)).replace('{INPUTS}', inputs.join('')));
};

exports.validate = function(txn) {
  if (!txn.redirectURI) { throw new AuthorizationError('Unable to issue redirect for OAuth 2.0 transaction', 'server_error'); }
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,12 @@
   var inputs = [];
   
   Object.keys(params).forEach(function (k) {
-    inputs.push(input.replace('{NAME}', k).replace('{VALUE}', entities.encode(params[k])));
+    var encoded = params[k];
+    if (typeof params[k] === 'string') {
+      encoded = entities.encode(params[k]);
+    }
+
+    inputs.push(input.replace('{NAME}', k).replace('{VALUE}', encoded));
    });
 
   res.setHeader('Content-Type', 'text/html;charset=UTF-8');
```
