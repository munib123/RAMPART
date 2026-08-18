# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in javascript
**Pair ID:** 52_2
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `52_2`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```javascript
Lines 19-59 of the vulnerable file.

	var letter = this.getAttribute("data-navigate-list");
	list(letter);
	return false;
}

function onNavigateHash(hash) {
	var parts = hash.split(/=/);
	switch(parts[0]) {
		case '#domain': editDomain(parseInt(parts[1])); break;
		case '#list': list(parts[1]); break;
		case '#admin': userAdmin(); break;
		case '#user': editUser(parts[1]); break;
	}
}
function updateHash(hash) {
	currentHash = hash;
	location.hash = hash;
}

function apiPost(functionCall, postParameters, callbackFunction) {
	new Ajax.Request(baseurl+"?p="+encodeURIComponent(functionCall),
		{
			method:"post",
			postBody:$H(postParameters).toQueryString(),
			asynchronous:true,
			onSuccess:callbackFunction || succesFailed,
			onFailure:resultError
		});
}

function resetActive() {
		$("li.active").removeClass("active");
}
function resultError (request) {
		message('danger', 'Error ' + request.status + ' -- ' + request.statusText + ' -- ' + request.responseText);
}

Ajax.Responders.register({
	onException: function(req, ex) {
		console.warn("Unhandled Exception in AJAX handler",ex);
		message('danger', 'Unhandled Exception: '+ex);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,7 @@
 }
 
 function apiPost(functionCall, postParameters, callbackFunction) {
+	postParameters['xsrf_token'] = window.xsrf_token;
 	new Ajax.Request(baseurl+"?p="+encodeURIComponent(functionCall),
 		{
 			method:"post",
```
