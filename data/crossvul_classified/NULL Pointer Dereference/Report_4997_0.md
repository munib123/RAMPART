# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4997_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4997_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 722-762 of the vulnerable file.

    }

    /* Check to see if client is locked out */
    if (isflagset(client.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
        *status = "CLIENT LOCKED OUT";
        return(KDC_ERR_CLIENT_REVOKED);
    }

    /* Check to see if server is locked out */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
        *status = "SERVICE LOCKED OUT";
        return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    /* Check to see if server is allowed to be a service */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_SVR)) {
        *status = "SERVICE NOT ALLOWED";
        return(KDC_ERR_MUST_USE_USER2USER);
    }

    if (check_anon(kdc_active_realm, request->client, request->server) != 0) {
        *status = "ANONYMOUS NOT ALLOWED";
        return(KDC_ERR_POLICY);
    }

    /* Perform KDB module policy checks. */
    ret = krb5_db_check_policy_as(kdc_context, request, &client, &server,
                                  kdc_time, status, e_data);
    if (ret && ret != KRB5_PLUGIN_OP_NOTSUPP)
        return errcode_to_protocol(ret);

    /* Check against local policy. */
    errcode = against_local_policy_as(request, client, server,
                                      kdc_time, status, e_data);
    if (errcode)
        return errcode;

    return 0;
}

int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -739,7 +739,7 @@
         return(KDC_ERR_MUST_USE_USER2USER);
     }
 
-    if (check_anon(kdc_active_realm, request->client, request->server) != 0) {
+    if (check_anon(kdc_active_realm, client.princ, request->server) != 0) {
         *status = "ANONYMOUS NOT ALLOWED";
         return(KDC_ERR_POLICY);
     }
```
