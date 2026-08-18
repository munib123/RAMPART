# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1537_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1537_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 953-993 of the vulnerable file.

    iakerb_gss_wrap,
#endif
#if defined(IOV_SHIM_EXERCISE_UNWRAP) || defined(IOV_SHIM_EXERCISE)
    NULL,
#else
    iakerb_gss_unwrap,
#endif
    krb5_gss_display_status,
    krb5_gss_indicate_mechs,
    krb5_gss_compare_name,
    krb5_gss_display_name,
    krb5_gss_import_name,
    krb5_gss_release_name,
    krb5_gss_inquire_cred,
    NULL,                /* add_cred */
#ifdef LEAN_CLIENT
    NULL,
    NULL,
#else
    iakerb_gss_export_sec_context,
    NULL,
#endif
    krb5_gss_inquire_cred_by_mech,
    krb5_gss_inquire_names_for_mech,
    iakerb_gss_inquire_context,
    krb5_gss_internal_release_oid,
    iakerb_gss_wrap_size_limit,
    krb5_gss_localname,
    krb5_gss_authorize_localname,
    krb5_gss_export_name,
    krb5_gss_duplicate_name,
    krb5_gss_store_cred,
    iakerb_gss_inquire_sec_context_by_oid,
    krb5_gss_inquire_cred_by_oid,
    iakerb_gss_set_sec_context_option,
    krb5_gssspi_set_cred_option,
    krb5_gssspi_mech_invoke,
    NULL,                /* wrap_aead */
    NULL,                /* unwrap_aead */
    iakerb_gss_wrap_iov,
    iakerb_gss_unwrap_iov,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -970,7 +970,7 @@
     NULL,
 #else
     iakerb_gss_export_sec_context,
-    NULL,
+    iakerb_gss_import_sec_context,
 #endif
     krb5_gss_inquire_cred_by_mech,
     krb5_gss_inquire_names_for_mech,
```
