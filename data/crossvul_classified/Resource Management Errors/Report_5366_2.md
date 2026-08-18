# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5366_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5366_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 316-356 of the vulnerable file.

        return APR_EINVAL;
    }
    if (h2_req_ignore_trailer(name, nlen)) {
        return APR_SUCCESS;
    }
    if (!stream->trailers) {
        stream->trailers = apr_table_make(stream->pool, 5);
    }
    hname = apr_pstrndup(stream->pool, name, nlen);
    hvalue = apr_pstrndup(stream->pool, value, vlen);
    h2_util_camel_case_header(hname, nlen);
    apr_table_mergen(stream->trailers, hname, hvalue);
    
    return APR_SUCCESS;
}

apr_status_t h2_stream_add_header(h2_stream *stream,
                                  const char *name, size_t nlen,
                                  const char *value, size_t vlen)
{
    ap_assert(stream);
    
    if (!stream->has_response) {
        if (name[0] == ':') {
            if ((vlen) > stream->session->s->limit_req_line) {
                /* pseudo header: approximation of request line size check */
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                              "h2_stream(%ld-%d): pseudo header %s too long", 
                              stream->session->id, stream->id, name);
                return h2_stream_set_error(stream, 
                                           HTTP_REQUEST_URI_TOO_LARGE);
            }
        }
        else if ((nlen + 2 + vlen) > stream->session->s->limit_req_fieldsize) {
            /* header too long */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
                          "h2_stream(%ld-%d): header %s too long", 
                          stream->session->id, stream->id, name);
            return h2_stream_set_error(stream, 
                                       HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -333,44 +333,49 @@
                                   const char *name, size_t nlen,
                                   const char *value, size_t vlen)
 {
+    int error = 0;
     ap_assert(stream);
     
-    if (!stream->has_response) {
-        if (name[0] == ':') {
-            if ((vlen) > stream->session->s->limit_req_line) {
-                /* pseudo header: approximation of request line size check */
-                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
-                              "h2_stream(%ld-%d): pseudo header %s too long", 
-                              stream->session->id, stream->id, name);
-                return h2_stream_set_error(stream, 
-                                           HTTP_REQUEST_URI_TOO_LARGE);
-            }
-        }
-        else if ((nlen + 2 + vlen) > stream->session->s->limit_req_fieldsize) {
-            /* header too long */
+    if (stream->has_response) {
+        return APR_EINVAL;    
+    }
+    ++stream->request_headers_added;
+    if (name[0] == ':') {
+        if ((vlen) > stream->session->s->limit_req_line) {
+            /* pseudo header: approximation of request line size check */
             ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
-                          "h2_stream(%ld-%d): header %s too long", 
+                          "h2_stream(%ld-%d): pseudo header %s too long", 
                           stream->session->id, stream->id, name);
-            return h2_stream_set_error(stream, 
-                                       HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
-        }
-        
-        if (name[0] != ':') {
-            ++stream->request_headers_added;
-            if (stream->request_headers_added 
-                > stream->session->s->limit_req_fields) {
-                /* too many header lines */
-                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
-                              "h2_stream(%ld-%d): too many header lines", 
-                              stream->session->id, stream->id);
-                return h2_stream_set_error(stream, 
-                                           HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
-            }
-        }
+            error = HTTP_REQUEST_URI_TOO_LARGE;
+        }
+    }
+    else if ((nlen + 2 + vlen) > stream->session->s->limit_req_fieldsize) {
+        /* header too long */
+        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
+                      "h2_stream(%ld-%d): header %s too long", 
+                      stream->session->id, stream->id, name);
+        error = HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
+    }
+    
+    if (stream->request_headers_added 
+        > stream->session->s->limit_req_fields + 4) {
+        /* too many header lines, include 4 pseudo headers */
+        if (stream->request_headers_added 
+            > stream->session->s->limit_req_fields + 4 + 100) {
+            /* yeah, right */
+            return APR_ECONNRESET;
+        }
+        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c,
+                      "h2_stream(%ld-%d): too many header lines", 
+                      stream->session->id, stream->id);
+        error = HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
     }
     
     if (h2_stream_is_scheduled(stream)) {
         return add_trailer(stream, name, nlen, value, vlen);
+    }
+    else if (error) {
+        return h2_stream_set_error(stream, error); 
     }
     else {
         if (!stream->rtmp) {
```
