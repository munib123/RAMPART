# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1533_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1533_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 284-324 of the vulnerable file.

                            void *arg)
{
    krb5_error_code retval = 0;
    krb5_data authp_data = {0, 0, NULL}, krb5_authz = {0, 0, NULL};
    krb5_pa_pk_as_req *reqp = NULL;
    krb5_pa_pk_as_req_draft9 *reqp9 = NULL;
    krb5_auth_pack *auth_pack = NULL;
    krb5_auth_pack_draft9 *auth_pack9 = NULL;
    pkinit_kdc_context plgctx = NULL;
    pkinit_kdc_req_context reqctx = NULL;
    krb5_checksum cksum = {0, 0, 0, NULL};
    krb5_data *der_req = NULL;
    int valid_eku = 0, valid_san = 0;
    krb5_data k5data;
    int is_signed = 1;
    krb5_pa_data **e_data = NULL;
    krb5_kdcpreauth_modreq modreq = NULL;

    pkiDebug("pkinit_verify_padata: entered!\n");
    if (data == NULL || data->length <= 0 || data->contents == NULL) {
        (*respond)(arg, 0, NULL, NULL, NULL);
        return;
    }


    if (moddata == NULL) {
        (*respond)(arg, EINVAL, NULL, NULL, NULL);
        return;
    }

    plgctx = pkinit_find_realm_context(context, moddata, request->server);
    if (plgctx == NULL) {
        (*respond)(arg, 0, NULL, NULL, NULL);
        return;
    }

#ifdef DEBUG_ASN1
    print_buffer_bin(data->contents, data->length, "/tmp/kdc_as_req");
#endif
    /* create a per-request context */
    retval = pkinit_init_kdc_req_context(context, &reqctx);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -301,7 +301,7 @@
 
     pkiDebug("pkinit_verify_padata: entered!\n");
     if (data == NULL || data->length <= 0 || data->contents == NULL) {
-        (*respond)(arg, 0, NULL, NULL, NULL);
+        (*respond)(arg, EINVAL, NULL, NULL, NULL);
         return;
     }
 
@@ -313,7 +313,7 @@
 
     plgctx = pkinit_find_realm_context(context, moddata, request->server);
     if (plgctx == NULL) {
-        (*respond)(arg, 0, NULL, NULL, NULL);
+        (*respond)(arg, EINVAL, NULL, NULL, NULL);
         return;
     }
 
```
