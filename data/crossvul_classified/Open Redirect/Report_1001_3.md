# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in c
**Pair ID:** 1001_3
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1001_3`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```c
Lines 3007-3047 of the vulnerable file.

	oidc_cache_set_sid(r, sid, NULL, 0);
	oidc_cache_set_session(r, uuid, NULL, 0);

	rc = OK;

out:

	if (jwk != NULL) {
		oidc_jwk_destroy(jwk);
		jwk = NULL;

	}
	if (jwt != NULL) {
		oidc_jwt_destroy(jwt);
		jwt = NULL;
	}

	return rc;
}

/*
 * perform (single) logout
 */
static int oidc_handle_logout(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {

	oidc_provider_t *provider = NULL;
	/* pickup the command or URL where the user wants to go after logout */
	char *url = NULL;
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_LOGOUT, &url);

	oidc_debug(r, "enter (url=%s)", url);

	if (oidc_is_front_channel_logout(url)) {
		return oidc_handle_logout_request(r, c, session, url);
	} else if (oidc_is_back_channel_logout(url)) {
		return oidc_handle_logout_backchannel(r, c);
	}

	if ((url == NULL) || (apr_strnatcmp(url, "") == 0)) {

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3024,6 +3024,53 @@
 	return rc;
 }
 
+static apr_byte_t oidc_validate_post_logout_url(request_rec *r, const char *url,
+		char **err_str, char **err_desc) {
+	apr_uri_t uri;
+	const char *c_host = NULL;
+
+	if (apr_uri_parse(r->pool, url, &uri) != APR_SUCCESS) {
+		*err_str = apr_pstrdup(r->pool, "Malformed URL");
+		*err_desc = apr_psprintf(r->pool, "Logout URL malformed: %s", url);
+		oidc_error(r, "%s: %s", *err_str, *err_desc);
+		return FALSE;
+	}
+
+	c_host = oidc_get_current_url_host(r);
+	if ((uri.hostname != NULL)
+			&& ((strstr(c_host, uri.hostname) == NULL)
+					|| (strstr(uri.hostname, c_host) == NULL))) {
+		*err_str = apr_pstrdup(r->pool, "Invalid Request");
+		*err_desc =
+				apr_psprintf(r->pool,
+						"logout value \"%s\" does not match the hostname of the current request \"%s\"",
+						apr_uri_unparse(r->pool, &uri, 0), c_host);
+		oidc_error(r, "%s: %s", *err_str, *err_desc);
+		return FALSE;
+	} else if (strstr(url, "/") != url) {
+		*err_str = apr_pstrdup(r->pool, "Malformed URL");
+		*err_desc =
+				apr_psprintf(r->pool,
+						"No hostname was parsed and it does not seem to be relative, i.e starting with '/': %s",
+						url);
+		oidc_error(r, "%s: %s", *err_str, *err_desc);
+		return FALSE;
+	}
+
+	/* validate the URL to prevent HTTP header splitting */
+	if (((strstr(url, "\n") != NULL) || strstr(url, "\r") != NULL)) {
+		*err_str = apr_pstrdup(r->pool, "Invalid Request");
+		*err_desc =
+				apr_psprintf(r->pool,
+						"logout value \"%s\" contains illegal \"\n\" or \"\r\" character(s)",
+						url);
+		oidc_error(r, "%s: %s", *err_str, *err_desc);
+		return FALSE;
+	}
+
+	return TRUE;
+}
+
 /*
  * perform (single) logout
  */
@@ -3033,6 +3080,9 @@
 	oidc_provider_t *provider = NULL;
 	/* pickup the command or URL where the user wants to go after logout */
 	char *url = NULL;
+	char *error_str = NULL;
+	char *error_description = NULL;
+
 	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_LOGOUT, &url);
 
 	oidc_debug(r, "enter (url=%s)", url);
@@ -3050,44 +3100,11 @@
 	} else {
 
 		/* do input validation on the logout parameter value */
-
-		const char *error_description = NULL;
-		apr_uri_t uri;
-
-		if (apr_uri_parse(r->pool, url, &uri) != APR_SUCCESS) {
-			const char *error_description = apr_psprintf(r->pool,
-					"Logout URL malformed: %s", url);
-			oidc_error(r, "%s", error_description);
-			return oidc_util_html_send_error(r, c->error_template,
-					"Malformed URL", error_description,
-					HTTP_INTERNAL_SERVER_ERROR);
-
-		}
-
-		const char *c_host = oidc_get_current_url_host(r);
-		if ((uri.hostname != NULL)
-				&& ((strstr(c_host, uri.hostname) == NULL)
-						|| (strstr(uri.hostname, c_host) == NULL))) {
-			error_description =
-					apr_psprintf(r->pool,
-							"logout value \"%s\" does not match the hostname of the current request \"%s\"",
-							apr_uri_unparse(r->pool, &uri, 0), c_host);
-			oidc_error(r, "%s", error_description);
-			return oidc_util_html_send_error(r, c->error_template,
-					"Invalid Request", error_description,
-					HTTP_INTERNAL_SERVER_ERROR);
-		}
-
-		/* validate the URL to prevent HTTP header splitting */
-		if (((strstr(url, "\n") != NULL) || strstr(url, "\r") != NULL)) {
-			error_description =
-					apr_psprintf(r->pool,
-							"logout value \"%s\" contains illegal \"\n\" or \"\r\" character(s)",
-							url);
-			oidc_error(r, "%s", error_description);
-			return oidc_util_html_send_error(r, c->error_template,
-					"Invalid Request", error_description,
-					HTTP_INTERNAL_SERVER_ERROR);
+		if (oidc_validate_post_logout_url(r, url, &error_str,
+				&error_description) == FALSE) {
+			return oidc_util_html_send_error(r, c->error_template, error_str,
+					error_description,
+					HTTP_BAD_REQUEST);
 		}
 	}
 
```
