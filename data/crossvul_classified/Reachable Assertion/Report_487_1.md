# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 487_1
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `487_1`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 99-139 of the vulnerable file.

    krb5_get_init_creds_opt_set_forwardable(opts, 0);
    krb5_get_init_creds_opt_set_proxiable(opts, 0);
    krb5_get_init_creds_opt_set_canonicalize(opts, 1);
    krb5_get_init_creds_opt_set_preauth_list(opts, ptypes, 1);

    if (in_creds->client != NULL) {
        client = *in_creds->client;
        client.realm = in_creds->server->realm;
    } else {
        client.magic = KV5M_PRINCIPAL;
        client.realm = in_creds->server->realm;
        /* should this be NULL, empty or a fixed string? XXX */
        client.data = NULL;
        client.length = 0;
        client.type = KRB5_NT_ENTERPRISE_PRINCIPAL;
    }

    code = k5_get_init_creds(context, &creds, &client, NULL, NULL, 0, NULL,
                             opts, krb5_get_as_key_noop, &userid, &use_master,
                             NULL);
    if (code == 0 || code == KRB5_PREAUTH_FAILED) {
        *canon_user = userid.user;
        userid.user = NULL;
        code = 0;
    }

cleanup:
    krb5_free_cred_contents(context, &creds);
    if (opts != NULL)
        krb5_get_init_creds_opt_free(context, opts);
    if (userid.user != NULL)
        krb5_free_principal(context, userid.user);

    return code;
}

static krb5_error_code
make_pa_for_user_checksum(krb5_context context,
                          krb5_keyblock *key,
                          krb5_pa_for_user *req,
                          krb5_checksum *cksum)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,7 +116,7 @@
     code = k5_get_init_creds(context, &creds, &client, NULL, NULL, 0, NULL,
                              opts, krb5_get_as_key_noop, &userid, &use_master,
                              NULL);
-    if (code == 0 || code == KRB5_PREAUTH_FAILED) {
+    if (!code || code == KRB5_PREAUTH_FAILED || code == KRB5KDC_ERR_KEY_EXP) {
         *canon_user = userid.user;
         userid.user = NULL;
         code = 0;
```
