# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 3184_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3184_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 647-687 of the vulnerable file.

	}

	/* check that we've got something back */
	if (token == NULL) {
		oidc_error(r, "could not resolve claims (token == NULL)");
		return oidc_oauth_return_www_authenticate(r, "invalid_token",
				"No claims could be parsed from the token");
	}

	/* store the parsed token (cq. the claims from the response) in the request state so it can be accessed by the authz routines */
	oidc_request_state_set(r, OIDC_CLAIMS_SESSION_KEY, (const char *) s_token);

	/* set the REMOTE_USER variable */
	if (oidc_oauth_set_remote_user(r, c, token) == FALSE) {
		oidc_error(r,
				"remote user could not be set, aborting with HTTP_UNAUTHORIZED");
		return oidc_oauth_return_www_authenticate(r, "invalid_token",
				"Could not set remote user");
	}

	/* set the user authentication HTTP header if set and required */
	char *authn_header = oidc_cfg_dir_authn_header(r);
	int pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	int pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);

	if ((r->user != NULL) && (authn_header != NULL)) {
		oidc_debug(r, "setting authn header (%s) to: %s", authn_header,
				r->user);
		apr_table_set(r->headers_in, authn_header, r->user);
	}

	/* set the resolved claims in the HTTP headers for the target application */
	oidc_util_set_app_infos(r, token, c->claim_prefix, c->claim_delimiter,
			pass_headers, pass_envvars);

	/* set the access_token in the app headers */
	if (access_token != NULL) {
		oidc_util_set_app_info(r, "access_token", access_token,
				OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -664,6 +664,12 @@
 				"Could not set remote user");
 	}
 
+	/*
+	 * we're going to pass the information that we have to the application,
+	 * but first we need to scrub the headers that we're going to use for security reasons
+	 */
+	oidc_scrub_headers(r);
+
 	/* set the user authentication HTTP header if set and required */
 	char *authn_header = oidc_cfg_dir_authn_header(r);
 	int pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
```
