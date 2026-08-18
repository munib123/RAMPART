# CrossVul Fix Pair: Improper Authentication in html
**Pair ID:** 4354_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4354_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```html
Lines 4-44 of the vulnerable file.

    <link rel="stylesheet" href="main.css" />
    <script src="main.js"></script>
    <script>
    if (location.pathname === "/docs"){location.pathname = "/docs/"};
    </script>
    <title>API Reference - ScratchVerifier Documentation</title>
</head>
<body><div id="body">

<h1 id="api-reference">API Reference</h1>
<p>The ScratchVerifier API is a HTTP/REST API for all operations.</p>
<p><b>API Base URL</b>: <a href="https://scratchverifier.ddns.net">https://scratchverifier.ddns.net</a></p>
<h2 id="authorization">Authorization</h2>
<p>Authorization is done using <a href="https://tools.ietf.org/html/rfc7617">Basic HTTP Authorization</a>, using your client ID as the username and token as the password.</p>
<table><caption>Example Authorization Header</caption>
<tr><td class="pre">Authorization: Basic MTAxMTQ3NjQ6NDY5MDI1YzYxM2RhNDMwYmEzMTE0NzIwY...==</td></tr>
</table>
<h2 id="api-endpoints">API Endpoints</h2>
<p>The simplicity of this API is such that there are only three total endpoints for its ultimate purpose.</p>
<h3 id="start/renew-verification-endpoint">Start/Renew Verification Endpoint</h3>
<p>Request a new verification code for a user. Only one code per user per client - if this endpoint is used again before the <a href="#finish-verification-endpoint">Finish Verification</a> endpoint is used, this will instead renew the 30-minute expiry on the code and return the original code.</p>
<div class="endpoint">
<div class="method-path auth-needed" onclick="showOrHide(this)"><span class="method">PUT</span> <code>/verify/<span class="param">{username}</span></code> <a href="#authorization"><img src="https://image.flaticon.com/icons/png/512/61/61457.png" title="Authorization necessary" /></a></div>
<div style="display: none">
<table><caption>URL Params</caption>
<tr><th>Field</th><th>Type</th><th>Description</th>
<tr><td>username</td><td>string</td><td>The username to verify</td></tr>
</table>
<table><caption>HTTP statuses</caption>
<tr><th>Status</th><th>Meaning</th>
<tr><td>200 OK</td><td>returns <a href="#verification-object">Verification</a> object</td></tr>
<tr><td>400 Bad Request</td><td>username is invalid by Scratch rules</td></tr>
<tr><td>401 Unauthorized</td><td>missing/invalid <a href="#authorization">authorization</a></td></tr>
</table>
<table><caption>Returns a <a href="#verification-object">Verification</a> object</caption>
<tr><td class="pre">{
  "code": "EJAAFcffGJeFDCGdJB...",
  "username": "scratchusername"
}</td></tr>
</table>
</div></div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,7 +21,7 @@
 <h2 id="api-endpoints">API Endpoints</h2>
 <p>The simplicity of this API is such that there are only three total endpoints for its ultimate purpose.</p>
 <h3 id="start/renew-verification-endpoint">Start/Renew Verification Endpoint</h3>
-<p>Request a new verification code for a user. Only one code per user per client - if this endpoint is used again before the <a href="#finish-verification-endpoint">Finish Verification</a> endpoint is used, this will instead renew the 30-minute expiry on the code and return the original code.</p>
+<p>Request a new verification code for a user. Only one code per user per client - if this endpoint is used again before the <a href="#finish-verification-endpoint">Finish Verification</a> endpoint is used, this will generate a new code and reset the 30-minute expiry, returning the new code instead.</p>
 <div class="endpoint">
 <div class="method-path auth-needed" onclick="showOrHide(this)"><span class="method">PUT</span> <code>/verify/<span class="param">{username}</span></code> <a href="#authorization"><img src="https://image.flaticon.com/icons/png/512/61/61457.png" title="Authorization necessary" /></a></div>
 <div style="display: none">
```
