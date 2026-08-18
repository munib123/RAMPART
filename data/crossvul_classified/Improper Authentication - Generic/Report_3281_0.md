# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 3281_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3281_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 2108-2148 of the vulnerable file.

    if (princs_ret == NULL && upn_ret == NULL && dns_ret == NULL) {
        pkiDebug("%s: nowhere to return any values!\n", __FUNCTION__);
        return retval;
    }

    if (cert == NULL) {
        pkiDebug("%s: no certificate!\n", __FUNCTION__);
        return retval;
    }

    X509_NAME_oneline(X509_get_subject_name(cert),
                      buf, sizeof(buf));
    pkiDebug("%s: looking for SANs in cert = %s\n", __FUNCTION__, buf);

    l = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (l < 0)
        return 0;

    if (!(ext = X509_get_ext(cert, l)) || !(ialt = X509V3_EXT_d2i(ext))) {
        pkiDebug("%s: found no subject alt name extensions\n", __FUNCTION__);
        retval = ENOENT;
        goto cleanup;
    }
    num_sans = sk_GENERAL_NAME_num(ialt);

    pkiDebug("%s: found %d subject alt name extension(s)\n", __FUNCTION__,
             num_sans);

    /* OK, we're likely returning something. Allocate return values */
    if (princs_ret != NULL) {
        princs = calloc(num_sans + 1, sizeof(krb5_principal));
        if (princs == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
    }
    if (upn_ret != NULL) {
        upns = calloc(num_sans + 1, sizeof(krb5_principal));
        if (upns == NULL) {
            retval = ENOMEM;
            goto cleanup;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2125,7 +2125,6 @@
 
     if (!(ext = X509_get_ext(cert, l)) || !(ialt = X509V3_EXT_d2i(ext))) {
         pkiDebug("%s: found no subject alt name extensions\n", __FUNCTION__);
-        retval = ENOENT;
         goto cleanup;
     }
     num_sans = sk_GENERAL_NAME_num(ialt);
@@ -2228,31 +2227,29 @@
     sk_GENERAL_NAME_pop_free(ialt, GENERAL_NAME_free);
 
     retval = 0;
-    if (princs)
+    if (princs != NULL && *princs != NULL) {
         *princs_ret = princs;
-    if (upns)
+        princs = NULL;
+    }
+    if (upns != NULL && *upns != NULL) {
         *upn_ret = upns;
-    if (dnss)
+        upns = NULL;
+    }
+    if (dnss != NULL && *dnss != NULL) {
         *dns_ret = dnss;
+        dnss = NULL;
+    }
 
 cleanup:
-    if (retval) {
-        if (princs != NULL) {
-            for (i = 0; princs[i] != NULL; i++)
-                krb5_free_principal(context, princs[i]);
-            free(princs);
-        }
-        if (upns != NULL) {
-            for (i = 0; upns[i] != NULL; i++)
-                krb5_free_principal(context, upns[i]);
-            free(upns);
-        }
-        if (dnss != NULL) {
-            for (i = 0; dnss[i] != NULL; i++)
-                free(dnss[i]);
-            free(dnss);
-        }
-    }
+    for (i = 0; princs != NULL && princs[i] != NULL; i++)
+        krb5_free_principal(context, princs[i]);
+    free(princs);
+    for (i = 0; upns != NULL && upns[i] != NULL; i++)
+        krb5_free_principal(context, upns[i]);
+    free(upns);
+    for (i = 0; dnss != NULL && dnss[i] != NULL; i++)
+        free(dnss[i]);
+    free(dnss);
     return retval;
 }
 
```
