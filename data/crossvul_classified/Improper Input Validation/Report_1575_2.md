# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1575_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1575_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 40-81 of the vulnerable file.

#include "http_vhost.h"
#include "http_connection.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "apr_date.h"           /* For apr_date_parse_http and APR_DATE_BAD */
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_time.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

APLOG_USE_MODULE(http);

#define INVALID_CHAR -2

typedef struct http_filter_ctx
{
    apr_off_t remaining;
    apr_off_t limit;
    apr_off_t limit_used;
    apr_int32_t chunk_used;
    apr_int16_t chunkbits;
    enum
    {
        BODY_NONE, /* streamed data */
        BODY_LENGTH, /* data constrained by content length */
        BODY_CHUNK, /* chunk expected */
        BODY_CHUNK_PART, /* chunk digits */
        BODY_CHUNK_EXT, /* chunk extension */
        BODY_CHUNK_DATA, /* data constrained by chunked encoding */
        BODY_CHUNK_END, /* chunk terminating CRLF */
        BODY_CHUNK_TRAILER /* trailers */
    } state;
    unsigned int eos_sent :1;
} http_ctx_t;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,15 +57,13 @@
 
 APLOG_USE_MODULE(http);
 
-#define INVALID_CHAR -2
-
 typedef struct http_filter_ctx
 {
     apr_off_t remaining;
     apr_off_t limit;
     apr_off_t limit_used;
     apr_int32_t chunk_used;
-    apr_int16_t chunkbits;
+    apr_int32_t chunkbits;
     enum
     {
         BODY_NONE, /* streamed data */
@@ -73,8 +71,10 @@
         BODY_CHUNK, /* chunk expected */
         BODY_CHUNK_PART, /* chunk digits */
         BODY_CHUNK_EXT, /* chunk extension */
+        BODY_CHUNK_LF, /* got CR, expect LF after digits/extension */
         BODY_CHUNK_DATA, /* data constrained by chunked encoding */
-        BODY_CHUNK_END, /* chunk terminating CRLF */
+        BODY_CHUNK_END, /* chunked data terminating CRLF */
+        BODY_CHUNK_END_LF, /* got CR, expect LF after data */
         BODY_CHUNK_TRAILER /* trailers */
     } state;
     unsigned int eos_sent :1;
@@ -89,7 +89,7 @@
  * In general, any negative number can be considered an overflow error.
  */
 static apr_status_t parse_chunk_size(http_ctx_t *ctx, const char *buffer,
-        apr_size_t len, int linelimit)
+                                     apr_size_t len, int linelimit)
 {
     apr_size_t i = 0;
 
@@ -99,9 +99,19 @@
         ap_xlate_proto_from_ascii(&c, 1);
 
         /* handle CRLF after the chunk */
-        if (ctx->state == BODY_CHUNK_END) {
+        if (ctx->state == BODY_CHUNK_END
+                || ctx->state == BODY_CHUNK_END_LF) {
             if (c == LF) {
                 ctx->state = BODY_CHUNK;
+            }
+            else if (c == CR && ctx->state == BODY_CHUNK_END) {
+                ctx->state = BODY_CHUNK_END_LF;
+            }
+            else {
+                /*
+                 * LF expected.
+                 */
+                return APR_EINVAL;
             }
             i++;
             continue;
@@ -111,28 +121,20 @@
         if (ctx->state == BODY_CHUNK) {
             if (!apr_isxdigit(c)) {
                 /*
-                 * Detect invalid character at beginning. This also works for empty
-                 * chunk size lines.
+                 * Detect invalid character at beginning. This also works for
+                 * empty chunk size lines.
                  */
-                return APR_EGENERAL;
+                return APR_EINVAL;
             }
             else {
                 ctx->state = BODY_CHUNK_PART;
             }
             ctx->remaining = 0;
-            ctx->chunkbits = sizeof(long) * 8;
+            ctx->chunkbits = sizeof(apr_off_t) * 8;
             ctx->chunk_used = 0;
         }
 
-        /* handle a chunk part, or a chunk extension */
-        /*
-         * In theory, we are supposed to expect CRLF only, but our
-         * test suite sends LF only. Tolerate a missing CR.
-         */
-        if (c == ';' || c == CR) {
-            ctx->state = BODY_CHUNK_EXT;
-        }
-        else if (c == LF) {
+        if (c == LF) {
             if (ctx->remaining) {
                 ctx->state = BODY_CHUNK_DATA;
             }
@@ -140,8 +142,28 @@
                 ctx->state = BODY_CHUNK_TRAILER;
             }
         }
-        else if (ctx->state != BODY_CHUNK_EXT) {
-            int xvalue = 0;
+        else if (ctx->state == BODY_CHUNK_LF) {
+            /*
+             * LF expected.
+             */
+            return APR_EINVAL;
+        }
+        else if (c == CR) {
+            ctx->state = BODY_CHUNK_LF;
+        }
+        else if (c == ';') {
+            ctx->state = BODY_CHUNK_EXT;
+        }
+        else if (ctx->state == BODY_CHUNK_EXT) {
+            /*
+             * Control chars (but tabs) are invalid.
+             */
+            if (c != '\t' && apr_iscntrl(c)) {
+                return APR_EINVAL;
+            }
+        }
+        else if (ctx->state == BODY_CHUNK_PART) {
+            int xvalue;
 
             /* ignore leading zeros */
             if (!ctx->remaining && c == '0') {
@@ -149,6 +171,12 @@
                 continue;
             }
 
+            ctx->chunkbits -= 4;
+            if (ctx->chunkbits < 0) {
+                /* overflow */
+                return APR_ENOSPC;
+            }
+
             if (c >= '0' && c <= '9') {
                 xvalue = c - '0';
             }
@@ -160,16 +188,18 @@
             }
             else {
                 /* bogus character */
-                return APR_EGENERAL;
+                return APR_EINVAL;
             }
 
             ctx->remaining = (ctx->remaining << 4) | xvalue;
-            ctx->chunkbits -= 4;
-            if (ctx->chunkbits <= 0 || ctx->remaining < 0) {
+            if (ctx->remaining < 0) {
                 /* overflow */
                 return APR_ENOSPC;
             }
-
+        }
+        else {
+            /* Should not happen */
+            return APR_EGENERAL;
         }
 
         i++;
@@ -232,7 +262,8 @@
  * are successfully parsed.
  */
 apr_status_t ap_http_filter(ap_filter_t *f, apr_bucket_brigade *b,
-        ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
+                            ap_input_mode_t mode, apr_read_type_e block,
+                            apr_off_t readbytes)
 {
     core_server_config *conf;
     apr_bucket *e;
@@ -282,8 +313,8 @@
                  * reading the connection until it is closed by the server."
                  */
                 ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(02555)
-                              "Unknown Transfer-Encoding: %s;"
-                              " using read-until-close", tenc);
+                              "Unknown Transfer-Encoding: %s; "
+                              "using read-until-close", tenc);
                 tenc = NULL;
             }
             else {
@@ -308,22 +339,20 @@
                     || endstr == lenp || *endstr || ctx->remaining < 0) {
 
                 ctx->remaining = 0;
-                ap_log_rerror(
-                        APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(01587)
-                        "Invalid Content-Length");
-
-                return APR_ENOSPC;
+                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(01587)
+                              "Invalid Content-Length");
+
+                return APR_EINVAL;
             }
 
             /* If we have a limit in effect and we know the C-L ahead of
              * time, stop it here if it is invalid.
              */
             if (ctx->limit && ctx->limit < ctx->remaining) {
-                ap_log_rerror(
-                        APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(01588)
-                        "Requested content-length of %" APR_OFF_T_FMT
-                        " is larger than the configured limit"
-                        " of %" APR_OFF_T_FMT, ctx->remaining, ctx->limit);
+                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, APLOGNO(01588)
+                          "Requested content-length of %" APR_OFF_T_FMT
+                          " is larger than the configured limit"
+                          " of %" APR_OFF_T_FMT, ctx->remaining, ctx->limit);
                 return APR_ENOSPC;
             }
         }
@@ -378,6 +407,7 @@
                 APR_BRIGADE_INSERT_TAIL(bb, e);
 
                 rv = ap_pass_brigade(f->c->output_filters, bb);
+                apr_brigade_cleanup(bb);
                 if (rv != APR_SUCCESS) {
                     return AP_FILTER_ERROR;
                 }
@@ -401,7 +431,9 @@
         case BODY_CHUNK:
         case BODY_CHUNK_PART:
         case BODY_CHUNK_EXT:
-        case BODY_CHUNK_END: {
+        case BODY_CHUNK_LF:
+        case BODY_CHUNK_END:
+        case BODY_CHUNK_END_LF: {
 
             rv = ap_get_brigade(f->next, b, AP_MODE_GETLINE, block, 0);
 
@@ -433,8 +465,9 @@
                                 f->r->server->limit_req_fieldsize);
                     }
                     if (rv != APR_SUCCESS) {
-                        ap_log_rerror(
... (diff truncated)
```
