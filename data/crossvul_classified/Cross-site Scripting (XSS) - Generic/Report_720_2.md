# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in c
**Pair ID:** 720_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `720_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```c
Lines 3089-3129 of the vulnerable file.

static int oidc_handle_session_management_iframe_rp(request_rec *r, oidc_cfg *c,
		oidc_session_t *session, const char *client_id,
		const char *check_session_iframe) {

	oidc_debug(r, "enter");

	const char *java_script =
			"    <script type=\"text/javascript\">\n"
			"      var targetOrigin  = '%s';\n"
			"      var message = '%s' + ' ' + '%s';\n"
			"	   var timerID;\n"
			"\n"
			"      function checkSession() {\n"
			"        console.debug('checkSession: posting ' + message + ' to ' + targetOrigin);\n"
			"        var win = window.parent.document.getElementById('%s').contentWindow;\n"
			"        win.postMessage( message, targetOrigin);\n"
			"      }\n"
			"\n"
			"      function setTimer() {\n"
			"        checkSession();\n"
			"        timerID = setInterval('checkSession()', %s);\n"
			"      }\n"
			"\n"
			"      function receiveMessage(e) {\n"
			"        console.debug('receiveMessage: ' + e.data + ' from ' + e.origin);\n"
			"        if (e.origin !== targetOrigin ) {\n"
			"          console.debug('receiveMessage: cross-site scripting attack?');\n"
			"          return;\n"
			"        }\n"
			"        if (e.data != 'unchanged') {\n"
			"          clearInterval(timerID);\n"
			"          if (e.data == 'changed') {\n"
			"		     window.location.href = '%s?session=check';\n"
			"          } else {\n"
			"		     window.location.href = '%s?session=logout';\n"
			"          }\n"
			"        }\n"
			"      }\n"
			"\n"
			"      window.addEventListener('message', receiveMessage, false);\n"
			"\n"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3106,7 +3106,7 @@
 			"\n"
 			"      function setTimer() {\n"
 			"        checkSession();\n"
-			"        timerID = setInterval('checkSession()', %s);\n"
+			"        timerID = setInterval('checkSession()', %d);\n"
 			"      }\n"
 			"\n"
 			"      function receiveMessage(e) {\n"
@@ -3149,12 +3149,13 @@
 
 	char *s_poll_interval = NULL;
 	oidc_util_get_request_parameter(r, "poll", &s_poll_interval);
-	if (s_poll_interval == NULL)
-		s_poll_interval = "3000";
+	int poll_interval = s_poll_interval ? strtol(s_poll_interval, NULL, 10) : 0;
+	if ((poll_interval <= 0) || (poll_interval > 3600 * 24))
+		poll_interval = 3000;
 
 	const char *redirect_uri = oidc_get_redirect_uri(r, c);
 	java_script = apr_psprintf(r->pool, java_script, origin, client_id,
-			session_state, op_iframe_id, s_poll_interval, redirect_uri,
+			session_state, op_iframe_id, poll_interval, redirect_uri,
 			redirect_uri);
 
 	return oidc_util_html_send(r, NULL, java_script, "setTimer", NULL, DONE);
```
