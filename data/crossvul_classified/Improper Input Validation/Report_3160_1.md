# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3160_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3160_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2828-2869 of the vulnerable file.

		return oidc_proto_javascript_implicit(r, c);
	}

	/* this is not an authorization response or logout request */

	/* check for "error" response */
	if (oidc_util_request_has_parameter(r, "error")) {

//		char *error = NULL, *descr = NULL;
//		oidc_util_get_request_parameter(r, "error", &error);
//		oidc_util_get_request_parameter(r, "error_description", &descr);
//
//		/* send user facing error to browser */
//		return oidc_util_html_send_error(r, error, descr, DONE);
		oidc_handle_redirect_authorization_response(r, c, session);
	}

	/* something went wrong */
	return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
			apr_psprintf(r->pool,
					"The OpenID Connect callback URL received an invalid request: %s",
					r->args), HTTP_INTERNAL_SERVER_ERROR);
}

/*
 * main routine: handle OpenID Connect authentication
 */
static int oidc_check_userid_openidc(request_rec *r, oidc_cfg *c) {

	if (c->redirect_uri == NULL) {
		oidc_error(r,
				"configuration error: the authentication type is set to \"openid-connect\" but OIDCRedirectURI has not been set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* check if this is a sub-request or an initial request */
	if (ap_is_initial_req(r)) {

		int rc = OK;

		/* load the session from the request state; this will be a new "empty" session if no state exists */
		oidc_session_t *session = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2845,8 +2845,8 @@
 	/* something went wrong */
 	return oidc_util_html_send_error(r, c->error_template, "Invalid Request",
 			apr_psprintf(r->pool,
-					"The OpenID Connect callback URL received an invalid request: %s",
-					r->args), HTTP_INTERNAL_SERVER_ERROR);
+					"The OpenID Connect callback URL received an invalid request"),
+					HTTP_INTERNAL_SERVER_ERROR);
 }
 
 /*
```
