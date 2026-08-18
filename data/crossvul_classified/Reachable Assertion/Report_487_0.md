# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 487_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `487_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 1590-1630 of the vulnerable file.

        if (!is_local_tgt && !issuing_referral) {
            /* A local server should not need a cross-realm TGT to impersonate
             * a local principal. */
            *status = "NOT_CROSS_REALM_REQUEST";
            return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN; /* match Windows error */
        }

        code = krb5_db_get_principal(kdc_context,
                                     (*s4u_x509_user)->user_id.user,
                                     KRB5_KDB_FLAG_INCLUDE_PAC, &princ);
        if (code == KRB5_KDB_NOENTRY) {
            *status = "UNKNOWN_S4U2SELF_PRINCIPAL";
            return KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
        } else if (code) {
            *status = "LOOKING_UP_S4U2SELF_PRINCIPAL";
            return code; /* caller can free for_user */
        }

        memset(&no_server, 0, sizeof(no_server));

        code = validate_as_request(kdc_active_realm, request, *princ,
                                   no_server, kdc_time, status, &e_data);
        if (code) {
            krb5_db_free_principal(kdc_context, princ);
            krb5_free_pa_data(kdc_context, e_data);
            return code;
        }

        *princ_ptr = princ;
    } else if (is_local_tgt) {
        /*
         * The server is asking to impersonate a principal from another realm,
         * using a local TGT.  It should instead ask that principal's realm and
         * follow referrals back to us.
         */
        *status = "S4U2SELF_CLIENT_NOT_OURS";
        return KRB5KDC_ERR_POLICY; /* match Windows error */
    }

    return 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1607,6 +1607,11 @@
 
         memset(&no_server, 0, sizeof(no_server));
 
+        /* Ignore password expiration and needchange attributes (as Windows
+         * does), since S4U2Self is not password authentication. */
+        princ->pw_expiration = 0;
+        clear(princ->attributes, KRB5_KDB_REQUIRES_PWCHANGE);
+
         code = validate_as_request(kdc_active_realm, request, *princ,
                                    no_server, kdc_time, status, &e_data);
         if (code) {
```
