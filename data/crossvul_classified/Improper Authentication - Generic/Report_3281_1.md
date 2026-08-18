# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 3281_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3281_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 170-213 of the vulnerable file.

                  pkinit_kdc_req_context reqctx,
                  krb5_kdcpreauth_callbacks cb,
                  krb5_kdcpreauth_rock rock,
                  krb5_const_principal client,
                  int *valid_san)
{
    krb5_error_code retval;
    krb5_principal *princs = NULL;
    krb5_principal *upns = NULL;
    int i;
#ifdef DEBUG_SAN_INFO
    char *client_string = NULL, *san_string;
#endif

    *valid_san = 0;
    retval = crypto_retrieve_cert_sans(context, plgctx->cryptoctx,
                                       reqctx->cryptoctx, plgctx->idctx,
                                       &princs,
                                       plgctx->opts->allow_upn ? &upns : NULL,
                                       NULL);
    if (retval == ENOENT) {
        TRACE_PKINIT_SERVER_NO_SAN(context);
        goto out;
    } else if (retval) {
        pkiDebug("%s: error from retrieve_certificate_sans()\n", __FUNCTION__);
        retval = KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
        goto out;
    }
    /* XXX Verify this is consistent with client side XXX */
#if 0
    retval = call_san_checking_plugins(context, plgctx, reqctx, princs,
                                       upns, NULL, &plugin_decision, &ignore);
    pkiDebug("%s: call_san_checking_plugins() returned retval %d\n",
             __FUNCTION__);
    if (retval) {
        retval = KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
        goto cleanup;
    }
    pkiDebug("%s: call_san_checking_plugins() returned decision %d\n",
             __FUNCTION__, plugin_decision);
    if (plugin_decision != NO_DECISION) {
        retval = plugin_decision;
        goto out;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -187,14 +187,18 @@
                                        &princs,
                                        plgctx->opts->allow_upn ? &upns : NULL,
                                        NULL);
-    if (retval == ENOENT) {
-        TRACE_PKINIT_SERVER_NO_SAN(context);
-        goto out;
-    } else if (retval) {
+    if (retval) {
         pkiDebug("%s: error from retrieve_certificate_sans()\n", __FUNCTION__);
         retval = KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
         goto out;
     }
+
+    if (princs == NULL && upns == NULL) {
+        TRACE_PKINIT_SERVER_NO_SAN(context);
+        retval = ENOENT;
+        goto out;
+    }
+
     /* XXX Verify this is consistent with client side XXX */
 #if 0
     retval = call_san_checking_plugins(context, plgctx, reqctx, princs,
@@ -1497,7 +1501,7 @@
         return KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE;
     }
 
-    return 0;
+    return KRB5_PLUGIN_NO_HANDLE;
 }
 
 static krb5_error_code
```
