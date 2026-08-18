# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1537_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1537_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1380-1420 of the vulnerable file.

                  gss_buffer_t input_message_buffer,
                  gss_buffer_t output_message_buffer, int *conf_state,
                  gss_qop_t *qop_state);

OM_uint32 KRB5_CALLCONV
iakerb_gss_unwrap_iov(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
                      int *conf_state, gss_qop_t *qop_state,
                      gss_iov_buffer_desc *iov, int iov_count);

OM_uint32 KRB5_CALLCONV
iakerb_gss_wrap_size_limit(OM_uint32 *minor_status,
                           gss_ctx_id_t context_handle, int conf_req_flag,
                           gss_qop_t qop_req, OM_uint32 req_output_size,
                           OM_uint32 *max_input_size);

#ifndef LEAN_CLIENT
OM_uint32 KRB5_CALLCONV
iakerb_gss_export_sec_context(OM_uint32 *minor_status,
                              gss_ctx_id_t *context_handle,
                              gss_buffer_t interprocess_token);
#endif /* LEAN_CLIENT */

OM_uint32 KRB5_CALLCONV
iakerb_gss_inquire_sec_context_by_oid(OM_uint32 *minor_status,
                                      const gss_ctx_id_t context_handle,
                                      const gss_OID desired_object,
                                      gss_buffer_set_t *data_set);

OM_uint32 KRB5_CALLCONV
iakerb_gss_set_sec_context_option(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  const gss_OID desired_object,
                                  const gss_buffer_t value);

OM_uint32 KRB5_CALLCONV
iakerb_gss_pseudo_random(OM_uint32 *minor_status, gss_ctx_id_t context_handle,
                         int prf_key, const gss_buffer_t prf_in,
                         ssize_t desired_output_len, gss_buffer_t prf_out);

/* Magic string to identify exported krb5 GSS credentials.  Increment this if
 * the format changes. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1397,6 +1397,11 @@
 iakerb_gss_export_sec_context(OM_uint32 *minor_status,
                               gss_ctx_id_t *context_handle,
                               gss_buffer_t interprocess_token);
+
+OM_uint32 KRB5_CALLCONV
+iakerb_gss_import_sec_context(OM_uint32 *minor_status,
+                              const gss_buffer_t interprocess_token,
+                              gss_ctx_id_t *context_handle);
 #endif /* LEAN_CLIENT */
 
 OM_uint32 KRB5_CALLCONV
```
