# CrossVul Fix Pair: DEPRECATED: Source Code in c
**Pair ID:** 1535_0
**Vulnerability Class:** DEPRECATED- Source Code
**CWE:** CWE-18
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1535_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Source Code

## Vulnerable Code
```c
Lines 603-643 of the vulnerable file.

 OM_uint32*,       /* time_rec */
 gss_cred_id_t*    /* delegated_cred_handle */
);

OM_uint32 KRB5_CALLCONV krb5_gss_accept_sec_context_ext
(OM_uint32*,       /* minor_status */
 gss_ctx_id_t*,    /* context_handle */
 gss_cred_id_t,    /* verifier_cred_handle */
 gss_buffer_t,     /* input_token_buffer */
 gss_channel_bindings_t,
 /* input_chan_bindings */
 gss_name_t*,      /* src_name */
 gss_OID*,         /* mech_type */
 gss_buffer_t,     /* output_token */
 OM_uint32*,       /* ret_flags */
 OM_uint32*,       /* time_rec */
 gss_cred_id_t*,   /* delegated_cred_handle */
 krb5_gss_ctx_ext_t/*exts */
);
#endif /* LEAN_CLIENT */

OM_uint32 KRB5_CALLCONV krb5_gss_process_context_token
(OM_uint32*,       /* minor_status */
 gss_ctx_id_t,     /* context_handle */
 gss_buffer_t      /* token_buffer */
);

OM_uint32 KRB5_CALLCONV krb5_gss_delete_sec_context
(OM_uint32*,       /* minor_status */
 gss_ctx_id_t*,    /* context_handle */
 gss_buffer_t      /* output_token */
);

OM_uint32 KRB5_CALLCONV krb5_gss_context_time
(OM_uint32*,       /* minor_status */
 gss_ctx_id_t,     /* context_handle */
 OM_uint32*        /* time_rec */
);

OM_uint32 KRB5_CALLCONV krb5_gss_display_status
(OM_uint32*,       /* minor_status */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -621,6 +621,21 @@
 );
 #endif /* LEAN_CLIENT */
 
+OM_uint32 KRB5_CALLCONV krb5_gss_inquire_sec_context_by_oid
+(OM_uint32*,       /* minor_status */
+ const gss_ctx_id_t,
+ /* context_handle */
+ const gss_OID,    /* desired_object */
+ gss_buffer_set_t* /* data_set */
+);
+
+OM_uint32 KRB5_CALLCONV krb5_gss_set_sec_context_option
+(OM_uint32*,       /* minor_status */
+ gss_ctx_id_t*,    /* context_handle */
+ const gss_OID,    /* desired_object */
+ const gss_buffer_t/* value */
+);
+
 OM_uint32 KRB5_CALLCONV krb5_gss_process_context_token
 (OM_uint32*,       /* minor_status */
  gss_ctx_id_t,     /* context_handle */
@@ -1302,6 +1317,105 @@
 krb5_gss_import_cred(OM_uint32 *minor_status, gss_buffer_t token,
                      gss_cred_id_t *cred_handle);
 
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_process_context_token(OM_uint32 *minor_status,
+                                 const gss_ctx_id_t context_handle,
+                                 const gss_buffer_t token_buffer);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_context_time(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                        OM_uint32 *time_rec);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_inquire_context(OM_uint32 *minor_status,
+                           gss_ctx_id_t context_handle, gss_name_t *src_name,
+                           gss_name_t *targ_name, OM_uint32 *lifetime_rec,
+                           gss_OID *mech_type, OM_uint32 *ctx_flags,
+                           int *locally_initiated, int *opened);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_get_mic(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                   gss_qop_t qop_req, gss_buffer_t message_buffer,
+                   gss_buffer_t message_token);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_get_mic_iov(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                       gss_qop_t qop_req, gss_iov_buffer_desc *iov,
+                       int iov_count);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_get_mic_iov_length(OM_uint32 *minor_status,
+                              gss_ctx_id_t context_handle, gss_qop_t qop_req,
+                              gss_iov_buffer_desc *iov, int iov_count);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_verify_mic(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                      gss_buffer_t msg_buffer, gss_buffer_t token_buffer,
+                      gss_qop_t *qop_state);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_verify_mic_iov(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                          gss_qop_t *qop_state, gss_iov_buffer_desc *iov,
+                          int iov_count);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_wrap(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                int conf_req_flag, gss_qop_t qop_req,
+                gss_buffer_t input_message_buffer, int *conf_state,
+                gss_buffer_t output_message_buffer);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_wrap_iov(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                    int conf_req_flag, gss_qop_t qop_req, int *conf_state,
+                    gss_iov_buffer_desc *iov, int iov_count);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_wrap_iov_length(OM_uint32 *minor_status,
+                           gss_ctx_id_t context_handle, int conf_req_flag,
+                           gss_qop_t qop_req, int *conf_state,
+                           gss_iov_buffer_desc *iov, int iov_count);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_unwrap(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                  gss_buffer_t input_message_buffer,
+                  gss_buffer_t output_message_buffer, int *conf_state,
+                  gss_qop_t *qop_state);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_unwrap_iov(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                      int *conf_state, gss_qop_t *qop_state,
+                      gss_iov_buffer_desc *iov, int iov_count);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_wrap_size_limit(OM_uint32 *minor_status,
+                           gss_ctx_id_t context_handle, int conf_req_flag,
+                           gss_qop_t qop_req, OM_uint32 req_output_size,
+                           OM_uint32 *max_input_size);
+
+#ifndef LEAN_CLIENT
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_export_sec_context(OM_uint32 *minor_status,
+                              gss_ctx_id_t *context_handle,
+                              gss_buffer_t interprocess_token);
+#endif /* LEAN_CLIENT */
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_inquire_sec_context_by_oid(OM_uint32 *minor_status,
+                                      const gss_ctx_id_t context_handle,
+                                      const gss_OID desired_object,
+                                      gss_buffer_set_t *data_set);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_set_sec_context_option(OM_uint32 *minor_status,
+                                  gss_ctx_id_t *context_handle,
+                                  const gss_OID desired_object,
+                                  const gss_buffer_t value);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_pseudo_random(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
+                         int prf_key, const gss_buffer_t prf_in,
+                         ssize_t desired_output_len, gss_buffer_t prf_out);
+
 /* Magic string to identify exported krb5 GSS credentials.  Increment this if
  * the format changes. */
 #define CRED_EXPORT_MAGIC "K5C1"
```
