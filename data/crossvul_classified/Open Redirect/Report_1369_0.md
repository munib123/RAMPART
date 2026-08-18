# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in c
**Pair ID:** 1369_0
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1369_0`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```c
Lines 3046-3086 of the vulnerable file.

						"logout value \"%s\" does not match the hostname of the current request \"%s\"",
						apr_uri_unparse(r->pool, &uri, 0), c_host);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	} else if ((uri.hostname == NULL) && (strstr(url, "/") != url)) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc =
				apr_psprintf(r->pool,
						"No hostname was parsed and it does not seem to be relative, i.e starting with '/': %s",
						url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
        } else if ((uri.hostname == NULL) && (strstr(url, "//") == url)) {
                *err_str = apr_pstrdup(r->pool, "Malformed URL");
                *err_desc =
                                apr_psprintf(r->pool,
                                                "No hostname was parsed and starting with '//': %s",
                                                url);
                oidc_error(r, "%s: %s", *err_str, *err_desc);
                return FALSE;
	}

	/* validate the URL to prevent HTTP header splitting */
	if (((strstr(url, "\n") != NULL) || strstr(url, "\r") != NULL)) {
		*err_str = apr_pstrdup(r->pool, "Invalid Request");
		*err_desc =
				apr_psprintf(r->pool,
						"logout value \"%s\" contains illegal \"\n\" or \"\r\" character(s)",
						url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	return TRUE;
}

/*
 * perform (single) logout
 */
static int oidc_handle_logout(request_rec *r, oidc_cfg *c,
		oidc_session_t *session) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3063,6 +3063,14 @@
                                                 url);
                 oidc_error(r, "%s: %s", *err_str, *err_desc);
                 return FALSE;
+        } else if ((uri.hostname == NULL) && (strstr(url, "/\\") == url)) {
+                *err_str = apr_pstrdup(r->pool, "Malformed URL");
+                *err_desc =
+                                apr_psprintf(r->pool,
+                                                "No hostname was parsed and starting with '/\\': %s",
+                                                url);
+                oidc_error(r, "%s: %s", *err_str, *err_desc);
+                return FALSE;
 	}
 
 	/* validate the URL to prevent HTTP header splitting */
```
