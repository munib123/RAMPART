# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 2556_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2556_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 315-355 of the vulnerable file.

}

/** process handshake packets from the client */
static void _sx_sasl_client_process(sx_t s, sx_plugin_t p, Gsasl_session *sd, const char *mech, const char *in, int inlen) {
    _sx_sasl_t ctx = (_sx_sasl_t) p->private;
    _sx_sasl_sess_t sctx = NULL;
    char *buf = NULL, *out = NULL, *realm = NULL, **ext_id;
    char hostname[256];
    int ret;
#ifdef HAVE_SSL
    int i;
#endif
    size_t buflen, outlen;

    assert(ctx);
    assert(ctx->cb);

    if(mech != NULL) {
        _sx_debug(ZONE, "auth request from client (mechanism=%s)", mech);

        if(!gsasl_server_support_p(ctx->gsasl_ctx, mech)) {
             _sx_debug(ZONE, "client requested mechanism (%s) that we didn't offer", mech);
             _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INVALID_MECHANISM, NULL), 0);
             return;
        }

        /* startup */
        ret = gsasl_server_start(ctx->gsasl_ctx, mech, &sd);
        if(ret != GSASL_OK) {
            _sx_debug(ZONE, "gsasl_server_start failed, no sasl for this conn; (%d): %s", ret, gsasl_strerror(ret));
            _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_TEMPORARY_FAILURE, gsasl_strerror(ret)), 0);
            return;
        }

        /* get the realm */
        (ctx->cb)(sx_sasl_cb_GET_REALM, NULL, (void **) &realm, s, ctx->cbarg);

        /* cleanup any existing session context */
        sctx = gsasl_session_hook_get(sd);
        if (sctx != NULL) free(sctx);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -332,7 +332,7 @@
     if(mech != NULL) {
         _sx_debug(ZONE, "auth request from client (mechanism=%s)", mech);
 
-        if(!gsasl_server_support_p(ctx->gsasl_ctx, mech)) {
+        if(!gsasl_server_support_p(ctx->gsasl_ctx, mech) || (ctx->cb)(sx_sasl_cb_CHECK_MECH, (void*)mech, NULL, s, ctx->cbarg) != sx_sasl_ret_OK) {
              _sx_debug(ZONE, "client requested mechanism (%s) that we didn't offer", mech);
              _sx_nad_write(s, _sx_sasl_failure(s, _sasl_err_INVALID_MECHANISM, NULL), 0);
              return;
```
