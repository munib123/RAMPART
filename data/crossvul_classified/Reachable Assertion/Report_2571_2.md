# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 2571_2
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2571_2`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 1203-1243 of the vulnerable file.

}

/*
 * Legacy protocol transition (Windows 2003 and above)
 */
static krb5_error_code
kdc_process_for_user(kdc_realm_t *kdc_active_realm,
                     krb5_pa_data *pa_data,
                     krb5_keyblock *tgs_session,
                     krb5_pa_s4u_x509_user **s4u_x509_user,
                     const char **status)
{
    krb5_error_code             code;
    krb5_pa_for_user            *for_user;
    krb5_data                   req_data;

    req_data.length = pa_data->length;
    req_data.data = (char *)pa_data->contents;

    code = decode_krb5_pa_for_user(&req_data, &for_user);
    if (code)
        return code;

    code = verify_for_user_checksum(kdc_context, tgs_session, for_user);
    if (code) {
        *status = "INVALID_S4U2SELF_CHECKSUM";
        krb5_free_pa_for_user(kdc_context, for_user);
        return code;
    }

    *s4u_x509_user = calloc(1, sizeof(krb5_pa_s4u_x509_user));
    if (*s4u_x509_user == NULL) {
        krb5_free_pa_for_user(kdc_context, for_user);
        return ENOMEM;
    }

    (*s4u_x509_user)->user_id.user = for_user->user;
    for_user->user = NULL;
    krb5_free_pa_for_user(kdc_context, for_user);

    return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1220,8 +1220,10 @@
     req_data.data = (char *)pa_data->contents;
 
     code = decode_krb5_pa_for_user(&req_data, &for_user);
-    if (code)
+    if (code) {
+        *status = "DECODE_PA_FOR_USER";
         return code;
+    }
 
     code = verify_for_user_checksum(kdc_context, tgs_session, for_user);
     if (code) {
@@ -1320,8 +1322,10 @@
     req_data.data = (char *)pa_data->contents;
 
     code = decode_krb5_pa_s4u_x509_user(&req_data, s4u_x509_user);
-    if (code)
+    if (code) {
+        *status = "DECODE_PA_S4U_X509_USER";
         return code;
+    }
 
     code = verify_s4u_x509_user_checksum(context,
                                          tgs_subkey ? tgs_subkey :
@@ -1624,6 +1628,7 @@
      * that is validated previously in validate_tgs_request().
      */
     if (request->kdc_options & (NON_TGT_OPTION | KDC_OPT_ENC_TKT_IN_SKEY)) {
+        *status = "INVALID_S4U2PROXY_OPTIONS";
         return KRB5KDC_ERR_BADOPTION;
     }
 
@@ -1631,6 +1636,7 @@
     if (!krb5_principal_compare(kdc_context,
                                 server->princ, /* after canon */
                                 server_princ)) {
+        *status = "EVIDENCE_TICKET_MISMATCH";
         return KRB5KDC_ERR_SERVER_NOMATCH;
     }
 
```
