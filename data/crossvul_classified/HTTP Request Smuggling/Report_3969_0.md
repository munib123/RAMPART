# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in c
**Pair ID:** 3969_0
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3969_0`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```c
Lines 40-81 of the vulnerable file.

ngx_str_t  ngx_http_lua_move_method = ngx_http_lua_method_name("MOVE");
ngx_str_t  ngx_http_lua_lock_method = ngx_http_lua_method_name("LOCK");
ngx_str_t  ngx_http_lua_mkcol_method =
        ngx_http_lua_method_name("MKCOL");
ngx_str_t  ngx_http_lua_propfind_method =
        ngx_http_lua_method_name("PROPFIND");
ngx_str_t  ngx_http_lua_proppatch_method =
        ngx_http_lua_method_name("PROPPATCH");
ngx_str_t  ngx_http_lua_unlock_method =
        ngx_http_lua_method_name("UNLOCK");
ngx_str_t  ngx_http_lua_patch_method =
        ngx_http_lua_method_name("PATCH");
ngx_str_t  ngx_http_lua_trace_method =
        ngx_http_lua_method_name("TRACE");


static ngx_str_t  ngx_http_lua_content_length_header_key =
    ngx_string("Content-Length");


static ngx_int_t ngx_http_lua_set_content_length_header(ngx_http_request_t *r,
    off_t len);
static ngx_int_t ngx_http_lua_adjust_subrequest(ngx_http_request_t *sr,
    ngx_uint_t method, int forward_body,
    ngx_http_request_body_t *body, unsigned vars_action,
    ngx_array_t *extra_vars);
static int ngx_http_lua_ngx_location_capture(lua_State *L);
static int ngx_http_lua_ngx_location_capture_multi(lua_State *L);
static void ngx_http_lua_process_vars_option(ngx_http_request_t *r,
    lua_State *L, int table, ngx_array_t **varsp);
static ngx_int_t ngx_http_lua_subrequest_add_extra_vars(ngx_http_request_t *r,
    ngx_array_t *extra_vars);
static ngx_int_t ngx_http_lua_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags);
static ngx_int_t ngx_http_lua_subrequest_resume(ngx_http_request_t *r);
static void ngx_http_lua_handle_subreq_responses(ngx_http_request_t *r,
    ngx_http_lua_ctx_t *ctx);
static void ngx_http_lua_cancel_subreq(ngx_http_request_t *r);
static ngx_int_t ngx_http_post_request_to_head(ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_copy_in_file_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_copy_request_headers(ngx_http_request_t *sr,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,8 +57,6 @@
     ngx_string("Content-Length");
 
 
-static ngx_int_t ngx_http_lua_set_content_length_header(ngx_http_request_t *r,
-    off_t len);
 static ngx_int_t ngx_http_lua_adjust_subrequest(ngx_http_request_t *sr,
     ngx_uint_t method, int forward_body,
     ngx_http_request_body_t *body, unsigned vars_action,
@@ -79,7 +77,7 @@
 static ngx_int_t ngx_http_post_request_to_head(ngx_http_request_t *r);
 static ngx_int_t ngx_http_lua_copy_in_file_request_body(ngx_http_request_t *r);
 static ngx_int_t ngx_http_lua_copy_request_headers(ngx_http_request_t *sr,
-    ngx_http_request_t *r);
+    ngx_http_request_t *pr, int pr_not_chunked);
 
 
 enum {
@@ -634,8 +632,8 @@
     unsigned vars_action, ngx_array_t *extra_vars)
 {
     ngx_http_request_t          *r;
-    ngx_int_t                    rc;
     ngx_http_core_main_conf_t   *cmcf;
+    int                          pr_not_chunked = 0;
     size_t                       size;
 
     r = sr->parent;
@@ -644,45 +642,31 @@
 
     if (body) {
         sr->request_body = body;
-
-        rc = ngx_http_lua_set_content_length_header(sr,
-                                                    body->buf
-                                                    ? ngx_buf_size(body->buf)
-                                                    : 0);
-
-        if (rc != NGX_OK) {
-            return NGX_ERROR;
-        }
 
     } else if (!always_forward_body
                && method != NGX_HTTP_PUT
                && method != NGX_HTTP_POST
                && r->headers_in.content_length_n > 0)
     {
-        rc = ngx_http_lua_set_content_length_header(sr, 0);
-        if (rc != NGX_OK) {
-            return NGX_ERROR;
-        }
-
-#if 1
         sr->request_body = NULL;
-#endif
 
     } else {
-        if (ngx_http_lua_copy_request_headers(sr, r) != NGX_OK) {
-            return NGX_ERROR;
-        }
-
-        if (sr->request_body) {
+        if (!r->headers_in.chunked) {
+            pr_not_chunked = 1;
+        }
+
+        if (sr->request_body && sr->request_body->temp_file) {
 
             /* deep-copy the request body */
 
-            if (sr->request_body->temp_file) {
-                if (ngx_http_lua_copy_in_file_request_body(sr) != NGX_OK) {
-                    return NGX_ERROR;
-                }
-            }
-        }
+            if (ngx_http_lua_copy_in_file_request_body(sr) != NGX_OK) {
+                return NGX_ERROR;
+            }
+        }
+    }
+
+    if (ngx_http_lua_copy_request_headers(sr, r, pr_not_chunked) != NGX_OK) {
+        return NGX_ERROR;
     }
 
     sr->method = method;
@@ -1134,100 +1118,6 @@
 }
 
 
-static ngx_int_t
-ngx_http_lua_set_content_length_header(ngx_http_request_t *r, off_t len)
-{
-    ngx_table_elt_t                 *h, *header;
-    u_char                          *p;
-    ngx_list_part_t                 *part;
-    ngx_http_request_t              *pr;
-    ngx_uint_t                       i;
-
-    r->headers_in.content_length_n = len;
-
-    if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
-                      sizeof(ngx_table_elt_t)) != NGX_OK)
-    {
-        return NGX_ERROR;
-    }
-
-    h = ngx_list_push(&r->headers_in.headers);
-    if (h == NULL) {
-        return NGX_ERROR;
-    }
-
-    h->key = ngx_http_lua_content_length_header_key;
-    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
-    if (h->lowcase_key == NULL) {
-        return NGX_ERROR;
-    }
-
-    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
-
-    r->headers_in.content_length = h;
-
-    p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
-    if (p == NULL) {
-        return NGX_ERROR;
-    }
-
-    h->value.data = p;
-
-    h->value.len = ngx_sprintf(h->value.data, "%O", len) - h->value.data;
-
-    h->hash = ngx_http_lua_content_length_hash;
-
-#if 0
-    dd("content length hash: %lu == %lu", (unsigned long) h->hash,
-       ngx_hash_key_lc((u_char *) "Content-Length",
-                       sizeof("Content-Length") - 1));
-#endif
-
-    dd("r content length: %.*s",
-       (int) r->headers_in.content_length->value.len,
-       r->headers_in.content_length->value.data);
-
-    pr = r->parent;
-
-    if (pr == NULL) {
-        return NGX_OK;
-    }
-
-    /* forward the parent request's all other request headers */
-
-    part = &pr->headers_in.headers.part;
-    header = part->elts;
-
-    for (i = 0; /* void */; i++) {
-
-        if (i >= part->nelts) {
-            if (part->next == NULL) {
-                break;
-            }
-
-            part = part->next;
-            header = part->elts;
-            i = 0;
-        }
-
-        if (header[i].key.len == sizeof("Content-Length") - 1
-            && ngx_strncasecmp(header[i].key.data, (u_char *) "Content-Length",
-                               sizeof("Content-Length") - 1) == 0)
-        {
-            continue;
-        }
-
-        if (ngx_http_lua_set_input_header(r, header[i].key,
-                                          header[i].value, 0) == NGX_ERROR)
-        {
-            return NGX_ERROR;
-        }
-    }
-
-    return NGX_OK;
-}
-
-
 static void
 ngx_http_lua_handle_subreq_responses(ngx_http_request_t *r,
     ngx_http_lua_ctx_t *ctx)
@@ -1742,11 +1632,17 @@
 
 
 static ngx_int_t
-ngx_http_lua_copy_request_headers(ngx_http_request_t *sr, ngx_http_request_t *r)
+ngx_http_lua_copy_request_headers(ngx_http_request_t *sr,
+    ngx_http_request_t *pr, int pr_not_chunked)
 {
-    ngx_table_elt_t                 *header;
+    ngx_table_elt_t                 *clh, *header;
     ngx_list_part_t                 *part;
     ngx_uint_t                       i;
+    u_char                          *p;
+    off_t                            len;
+
+    dd("before: parent req headers count: %d",
+       (int) pr->headers_in.headers.part.nelts);
 
     if (ngx_list_init(&sr->headers_in.headers, sr->pool, 20,
                       sizeof(ngx_table_elt_t)) != NGX_OK)
@@ -1754,10 +1650,46 @@
         return NGX_ERROR;
     }
 
-    dd("before: parent req headers count: %d",
-       (int) r->headers_in.headers.part.nelts);
-
-    part = &r->headers_in.headers.part;
+    if (sr->request_body && !pr_not_chunked) {
+
+        /* craft our own Content-Length */
+
+        len = sr->request_body->buf ? ngx_buf_size(sr->request_body->buf) : 0;
+
+        clh = ngx_list_push(&sr->headers_in.headers);
+        if (clh == NULL) {
+            return NGX_ERROR;
+        }
+
+        clh->hash = ngx_http_lua_content_length_hash;
+        clh->key = ngx_http_lua_content_length_header_key;
+        clh->lowcase_key = ngx_pnalloc(sr->pool, clh->key.len);
+        if (clh->lowcase_key == NULL) {
+            return NGX_ERROR;
+        }
+
+        ngx_strlow(clh->lowcase_key, clh->key.data, clh->key.len);
+
+        p = ngx_palloc(sr->pool, NGX_OFF_T_LEN);
+        if (p == NULL) {
+            return NGX_ERROR;
+        }
+
+        clh->value.data = p;
+        clh->value.len = ngx_sprintf(clh->value.data, "%O", len)
+                         - clh->value.data;
+
+        sr->headers_in.content_length = clh;
+        sr->headers_in.content_length_n = len;
+
+        dd("sr crafted content-length: %.*s",
+           (int) sr->headers_in.content_length->value.len,
+           sr->headers_in.content_length->value.data);
+    }
+
+    /* copy the parent request's headers */
+
+    part = &pr->headers_in.headers.part;
     header = part->elts;
 
     for (i = 0; /* void */; i++) {
@@ -1772,7 +1704,14 @@
             i = 0;
         }
 
-        dd("setting request header %.*s: %.*s", (int) header[i].key.len,
+        if (!pr_not_chunked && header[i].key.len == sizeof("Content-Length") - 1
+            && ngx_strncasecmp(header[i].key.data, (u_char *) "Content-Length",
+                               sizeof("Content-Length") - 1) == 0)
+        {
+            continue;
+        }
+
+        dd("sr copied req header %.*s: %.*s", (int) header[i].key.len,
... (diff truncated)
```
