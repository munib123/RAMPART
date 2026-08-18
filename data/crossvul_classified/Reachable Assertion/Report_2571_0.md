# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 2571_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2571_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 349-390 of the vulnerable file.

                                  &state->reply, &response);
    if (state->client_key != NULL)
        state->reply.enc_part.kvno = state->client_key->key_data_kvno;
    if (errcode) {
        state->status = "ENCODE_KDC_REP";
        goto egress;
    }

    /* these parts are left on as a courtesy from krb5_encode_kdc_rep so we
       can use them in raw form if needed.  But, we don't... */
    memset(state->reply.enc_part.ciphertext.data, 0,
           state->reply.enc_part.ciphertext.length);
    free(state->reply.enc_part.ciphertext.data);

    log_as_req(kdc_context, state->local_addr, state->remote_addr,
               state->request, &state->reply, state->client, state->cname,
               state->server, state->sname, state->authtime, 0, 0, 0);
    did_log = 1;

egress:
    if (errcode != 0)
        assert (state->status != 0);

    au_state->status = state->status;
    au_state->reply = &state->reply;
    kau_as_req(kdc_context,
              (errcode || state->preauth_err) ? FALSE : TRUE, au_state);
    kau_free_kdc_req(au_state);

    free_padata_context(kdc_context, state->pa_context);
    if (as_encrypting_key)
        krb5_free_keyblock(kdc_context, as_encrypting_key);
    if (errcode)
        emsg = krb5_get_error_message(kdc_context, errcode);

    if (state->status) {
        log_as_req(kdc_context, state->local_addr, state->remote_addr,
                   state->request, &state->reply, state->client,
                   state->cname, state->server, state->sname, state->authtime,
                   state->status, errcode, emsg);
        did_log = 1;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -366,8 +366,8 @@
     did_log = 1;
 
 egress:
-    if (errcode != 0)
-        assert (state->status != 0);
+    if (errcode != 0 && state->status == NULL)
+        state->status = "UNKNOWN_REASON";
 
     au_state->status = state->status;
     au_state->reply = &state->reply;
```
