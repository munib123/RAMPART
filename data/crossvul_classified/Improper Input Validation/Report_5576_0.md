# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5576_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5576_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1040-1080 of the vulnerable file.


    /* the first entry in this array is for krbtgt/local@local, so we
       ignore it */
    while (--pl2 > plist) {
        tmp = *krb5_princ_realm(kdc_context, *pl2);
        krb5_princ_set_realm(kdc_context, *pl2,
                             krb5_princ_realm(kdc_context, tgs_server));
        retval = db_get_svc_princ(kdc_context, *pl2, 0, &server, status);
        krb5_princ_set_realm(kdc_context, *pl2, &tmp);
        if (retval == KRB5_KDB_NOENTRY)
            continue;
        else if (retval)
            goto cleanup;

        log_tgs_alt_tgt(kdc_context, server->princ);
        *server_ptr = server;
        server = NULL;
        goto cleanup;
    }
cleanup:
    if (retval != 0)
        *status = "UNKNOWN_SERVER";

    krb5_free_realm_tree(kdc_context, plist);
    krb5_db_free_principal(kdc_context, server);
    return retval;
}

/*
 * Check whether the request satisfies the conditions for generating a referral
 * TGT.  The caller checks whether the hostname component looks like a FQDN.
 */
static krb5_boolean
is_referral_req(kdc_realm_t *kdc_active_realm, krb5_kdc_req *request)
{
    krb5_boolean ret = FALSE;
    char *stype = NULL;
    char *ref_services = kdc_active_realm->realm_host_based_services;
    char *nonref_services = kdc_active_realm->realm_no_host_referral;

    if (!(request->kdc_options & KDC_OPT_CANONICALIZE))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1057,6 +1057,8 @@
         goto cleanup;
     }
 cleanup:
+    if (retval == 0 && server_ptr == NULL)
+        retval = KRB5_KDB_NOENTRY;
     if (retval != 0)
         *status = "UNKNOWN_SERVER";
 
@@ -1149,7 +1151,7 @@
         goto cleanup;
     }
     /* Don't return a referral to the empty realm or the service realm. */
-    if (realms == NULL || realms[0] == '\0' ||
+    if (realms == NULL || realms[0] == NULL || *realms[0] == '\0' ||
         data_eq_string(srealm, realms[0])) {
         retval = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
         goto cleanup;
```
