# CrossVul Fix Pair: DEPRECATED: Source Code in c
**Pair ID:** 1535_1
**Vulnerability Class:** DEPRECATED- Source Code
**CWE:** CWE-18
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1535_1`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Source Code

## Vulnerable Code
```c
Lines 334-374 of the vulnerable file.

        gss_krb5int_get_tkt_flags
    },
    {
        {GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID},
        gss_krb5int_extract_authz_data_from_sec_context
    },
    {
        {GSS_KRB5_INQ_SSPI_SESSION_KEY_OID_LENGTH, GSS_KRB5_INQ_SSPI_SESSION_KEY_OID},
        gss_krb5int_inq_session_key
    },
    {
        {GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID},
        gss_krb5int_export_lucid_sec_context
    },
    {
        {GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID_LENGTH, GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID},
        gss_krb5int_extract_authtime_from_sec_context
    }
};

static OM_uint32 KRB5_CALLCONV
krb5_gss_inquire_sec_context_by_oid (OM_uint32 *minor_status,
                                     const gss_ctx_id_t context_handle,
                                     const gss_OID desired_object,
                                     gss_buffer_set_t *data_set)
{
    krb5_gss_ctx_id_rec *ctx;
    size_t i;

    if (minor_status == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    if (desired_object == GSS_C_NO_OID)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (data_set == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    *data_set = GSS_C_NO_BUFFER_SET;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -351,7 +351,7 @@
     }
 };
 
-static OM_uint32 KRB5_CALLCONV
+OM_uint32 KRB5_CALLCONV
 krb5_gss_inquire_sec_context_by_oid (OM_uint32 *minor_status,
                                      const gss_ctx_id_t context_handle,
                                      const gss_OID desired_object,
@@ -465,7 +465,7 @@
 };
 #endif
 
-static OM_uint32 KRB5_CALLCONV
+OM_uint32 KRB5_CALLCONV
 krb5_gss_set_sec_context_option (OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  const gss_OID desired_object,
@@ -929,20 +929,103 @@
     krb5_gss_get_mic_iov_length,
 };
 
+/* Functions which use security contexts or acquire creds are IAKERB-specific;
+ * other functions can borrow from the krb5 mech. */
+static struct gss_config iakerb_mechanism = {
+    { GSS_MECH_KRB5_OID_LENGTH, GSS_MECH_KRB5_OID },
+    NULL,
+    iakerb_gss_acquire_cred,
+    krb5_gss_release_cred,
+    iakerb_gss_init_sec_context,
+#ifdef LEAN_CLIENT
+    NULL,
+#else
+    iakerb_gss_accept_sec_context,
+#endif
+    iakerb_gss_process_context_token,
+    iakerb_gss_delete_sec_context,
+    iakerb_gss_context_time,
+    iakerb_gss_get_mic,
+    iakerb_gss_verify_mic,
+#if defined(IOV_SHIM_EXERCISE_WRAP) || defined(IOV_SHIM_EXERCISE)
+    NULL,
+#else
+    iakerb_gss_wrap,
+#endif
+#if defined(IOV_SHIM_EXERCISE_UNWRAP) || defined(IOV_SHIM_EXERCISE)
+    NULL,
+#else
+    iakerb_gss_unwrap,
+#endif
+    krb5_gss_display_status,
+    krb5_gss_indicate_mechs,
+    krb5_gss_compare_name,
+    krb5_gss_display_name,
+    krb5_gss_import_name,
+    krb5_gss_release_name,
+    krb5_gss_inquire_cred,
+    NULL,                /* add_cred */
+#ifdef LEAN_CLIENT
+    NULL,
+    NULL,
+#else
+    iakerb_gss_export_sec_context,
+    NULL,
+#endif
+    krb5_gss_inquire_cred_by_mech,
+    krb5_gss_inquire_names_for_mech,
+    iakerb_gss_inquire_context,
+    krb5_gss_internal_release_oid,
+    iakerb_gss_wrap_size_limit,
+    krb5_gss_localname,
+    krb5_gss_authorize_localname,
+    krb5_gss_export_name,
+    krb5_gss_duplicate_name,
+    krb5_gss_store_cred,
+    iakerb_gss_inquire_sec_context_by_oid,
+    krb5_gss_inquire_cred_by_oid,
+    iakerb_gss_set_sec_context_option,
+    krb5_gssspi_set_cred_option,
+    krb5_gssspi_mech_invoke,
+    NULL,                /* wrap_aead */
+    NULL,                /* unwrap_aead */
+    iakerb_gss_wrap_iov,
+    iakerb_gss_unwrap_iov,
+    iakerb_gss_wrap_iov_length,
+    NULL,               /* complete_auth_token */
+    NULL,               /* acquire_cred_impersonate_name */
+    NULL,               /* add_cred_impersonate_name */
+    NULL,               /* display_name_ext */
+    krb5_gss_inquire_name,
+    krb5_gss_get_name_attribute,
+    krb5_gss_set_name_attribute,
+    krb5_gss_delete_name_attribute,
+    krb5_gss_export_name_composite,
+    krb5_gss_map_name_to_any,
+    krb5_gss_release_any_name_mapping,
+    iakerb_gss_pseudo_random,
+    NULL,               /* set_neg_mechs */
+    krb5_gss_inquire_saslname_for_mech,
+    krb5_gss_inquire_mech_for_saslname,
+    krb5_gss_inquire_attrs_for_mech,
+    krb5_gss_acquire_cred_from,
+    krb5_gss_store_cred_into,
+    iakerb_gss_acquire_cred_with_password,
+    krb5_gss_export_cred,
+    krb5_gss_import_cred,
+    NULL,               /* import_sec_context_by_mech */
+    NULL,               /* import_name_by_mech */
+    NULL,               /* import_cred_by_mech */
+    iakerb_gss_get_mic_iov,
+    iakerb_gss_verify_mic_iov,
+    iakerb_gss_get_mic_iov_length,
+};
+
 #ifdef _GSS_STATIC_LINK
 #include "mglueP.h"
 static int gss_iakerbmechglue_init(void)
 {
     struct gss_mech_config mech_iakerb;
-    struct gss_config iakerb_mechanism = krb5_mechanism;
-
-    /* IAKERB mechanism mirrors krb5, but with different context SPIs */
-    iakerb_mechanism.gss_accept_sec_context = iakerb_gss_accept_sec_context;
-    iakerb_mechanism.gss_init_sec_context   = iakerb_gss_init_sec_context;
-    iakerb_mechanism.gss_delete_sec_context = iakerb_gss_delete_sec_context;
-    iakerb_mechanism.gss_acquire_cred       = iakerb_gss_acquire_cred;
-    iakerb_mechanism.gssspi_acquire_cred_with_password
-                                    = iakerb_gss_acquire_cred_with_password;
 
     memset(&mech_iakerb, 0, sizeof(mech_iakerb));
     mech_iakerb.mech = &iakerb_mechanism;
```
