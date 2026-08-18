# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 3184_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3184_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 115-155 of the vulnerable file.

		 */
		const int prefix_matches = (k != NULL) && prefix_len
				&& (oidc_strnenvcmp(k, claim_prefix, prefix_len) == 0);

		/* add to the clean_headers if non-suspicious, skip and report otherwise */
		if (!prefix_matches && !authn_header_matches) {
			apr_table_addn(clean_headers, k, e[i].val);
		} else {
			oidc_warn(r, "scrubbed suspicious request header (%s: %.32s)", k,
					e[i].val);
		}
	}

	/* overwrite the incoming headers with the cleaned result */
	r->headers_in = clean_headers;
}

/*
 * scrub all mod_auth_openidc related headers
 */
static void oidc_scrub_headers(request_rec *r) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_openidc_module);

	if (cfg->scrub_request_headers != 0) {

		/* scrub all headers starting with OIDC_ first */
		oidc_scrub_request_headers(r, OIDC_DEFAULT_HEADER_PREFIX,
				oidc_cfg_dir_authn_header(r));

		/*
		 * then see if the claim headers need to be removed on top of that
		 * (i.e. the prefix does not start with the default OIDC_)
		 */
		if ((strstr(cfg->claim_prefix, OIDC_DEFAULT_HEADER_PREFIX)
				!= cfg->claim_prefix)) {
			oidc_scrub_request_headers(r, cfg->claim_prefix, NULL);
		}
	}
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,7 +132,7 @@
 /*
  * scrub all mod_auth_openidc related headers
  */
-static void oidc_scrub_headers(request_rec *r) {
+void oidc_scrub_headers(request_rec *r) {
 	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
 			&auth_openidc_module);
 
```
