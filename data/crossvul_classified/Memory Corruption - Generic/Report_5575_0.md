# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5575_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5575_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1124-1164 of the vulnerable file.

     *      the name type is NT-SRV-HST
     *      or name type is NT-UNKNOWN and
     *         the 1st component is listed in conf file under host_based_services
     * the 1st component is not in a list in conf under "no_host_referral"
     * the 2d component looks like fully-qualified domain name (FQDN)
     * If all of these conditions are satisfied - try mapping the FQDN and
     * re-process the request as if client had asked for cross-realm TGT.
     */
    if (isflagset(request->kdc_options, KDC_OPT_CANONICALIZE) &&
        !isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY) &&
        krb5_princ_size(kdc_context, request->server) == 2) {

        comp1 = krb5_princ_component(kdc_context, request->server, 0);
        comp2 = krb5_princ_component(kdc_context, request->server, 1);

        comp1_str = calloc(1,comp1->length+1);
        if (!comp1_str) {
            retval = ENOMEM;
            goto cleanup;
        }
        strlcpy(comp1_str,comp1->data,comp1->length+1);

        if ((krb5_princ_type(kdc_context, request->server) == KRB5_NT_SRV_HST ||
             krb5_princ_type(kdc_context, request->server) == KRB5_NT_SRV_INST ||
             (krb5_princ_type(kdc_context, request->server) == KRB5_NT_UNKNOWN &&
              kdc_active_realm->realm_host_based_services != NULL &&
              (krb5_match_config_pattern(kdc_active_realm->realm_host_based_services,
                                         comp1_str) == TRUE ||
               krb5_match_config_pattern(kdc_active_realm->realm_host_based_services,
                                         KRB5_CONF_ASTERISK) == TRUE))) &&
            (kdc_active_realm->realm_no_host_referral == NULL ||
             (krb5_match_config_pattern(kdc_active_realm->realm_no_host_referral,
                                        KRB5_CONF_ASTERISK) == FALSE &&
              krb5_match_config_pattern(kdc_active_realm->realm_no_host_referral,
                                        comp1_str) == FALSE))) {

            if (memchr(comp2->data, '.', comp2->length) == NULL)
                goto cleanup;
            temp_buf = calloc(1, comp2->length+1);
            if (!temp_buf) {
                retval = ENOMEM;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1141,7 +1141,8 @@
             retval = ENOMEM;
             goto cleanup;
         }
-        strlcpy(comp1_str,comp1->data,comp1->length+1);
+        if (comp1->data != NULL)
+            memcpy(comp1_str, comp1->data, comp1->length);
 
         if ((krb5_princ_type(kdc_context, request->server) == KRB5_NT_SRV_HST ||
              krb5_princ_type(kdc_context, request->server) == KRB5_NT_SRV_INST ||
@@ -1164,7 +1165,8 @@
                 retval = ENOMEM;
                 goto cleanup;
             }
-            strlcpy(temp_buf, comp2->data,comp2->length+1);
+            if (comp2->data != NULL)
+                memcpy(temp_buf, comp2->data, comp2->length);
             retval = krb5int_get_domain_realm_mapping(kdc_context, temp_buf, &realms);
             free(temp_buf);
             if (retval) {
```
