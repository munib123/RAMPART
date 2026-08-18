# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 3184_3
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3184_3`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 370-410 of the vulnerable file.

	int cookie_http_only;

	char *outgoing_proxy;

	char *crypto_passphrase;

	int provider_metadata_refresh_interval;

} oidc_cfg;

int oidc_check_user_id(request_rec *r);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status oidc_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args);
#else
int oidc_auth_checker(request_rec *r);
#endif
void oidc_request_state_set(request_rec *r, const char *key, const char *value);
const char*oidc_request_state_get(request_rec *r, const char *key);
int oidc_handle_jwks(request_rec *r, oidc_cfg *c);
apr_byte_t oidc_post_preserve_javascript(request_rec *r, const char *location, char **javascript, char **javascript_method);

// oidc_oauth
int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c);

// oidc_proto.c
char *oidc_proto_peek_jwt_header(request_rec *r, const char *jwt, char **alg);
int oidc_proto_authorization_request(request_rec *r, struct oidc_provider_t *provider, const char *login_hint, const char *redirect_uri, const char *state, json_t *proto_state, const char *id_token_hint, const char *code_challenge, const char *auth_request_params);
apr_byte_t oidc_proto_is_post_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_is_redirect_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_refresh_request(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *rtoken, char **id_token, char **access_token, char **token_type, int *expires_in, char **refresh_token);
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *id_token_sub, const char *access_token, const char **response);
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg, const char *acct, char **issuer);
apr_byte_t oidc_proto_url_based_discovery(request_rec *r, oidc_cfg *cfg, const char *url, char **issuer);
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *id_token, const char *nonce, oidc_jwt_t **jwt, apr_byte_t is_code_flow);
int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c);
apr_array_header_t *oidc_proto_supported_flows(apr_pool_t *pool);
apr_byte_t oidc_proto_flow_is_supported(apr_pool_t *pool, const char *flow);
apr_byte_t oidc_proto_validate_authorization_response(request_rec *r, const char *response_type, const char *requested_response_mode, char **code, char **id_token, char **access_token, char **token_type, const char *used_response_mode);
apr_byte_t oidc_proto_jwt_verify(request_rec *r, oidc_cfg *cfg, oidc_jwt_t *jwt, const oidc_jwks_uri_t *jwks_uri, apr_hash_t *symmetric_keys);
apr_byte_t oidc_proto_validate_jwt(request_rec *r, oidc_jwt_t *jwt, const char *iss, apr_byte_t exp_is_mandatory, apr_byte_t iat_is_mandatory, int iat_slack);
apr_byte_t oidc_proto_generate_nonce(request_rec *r, char **nonce, int len);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -387,6 +387,7 @@
 const char*oidc_request_state_get(request_rec *r, const char *key);
 int oidc_handle_jwks(request_rec *r, oidc_cfg *c);
 apr_byte_t oidc_post_preserve_javascript(request_rec *r, const char *location, char **javascript, char **javascript_method);
+void oidc_scrub_headers(request_rec *r);
 
 // oidc_oauth
 int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c);
```
