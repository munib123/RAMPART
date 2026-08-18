# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2253_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2253_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 82-122 of the vulnerable file.

pthread_key_t request_list;

/* Create a memory allocation in order to handle the request data */
static inline void mk_request_init(struct session_request *request)
{
    request->status = MK_TRUE;
    request->method = MK_HTTP_METHOD_UNKNOWN;

    request->file_info.size = -1;

    request->bytes_to_send = -1;
    request->fd_file = -1;

    /* Response Headers */
    mk_header_response_reset(&request->headers);
}

void mk_request_free(struct session_request *sr)
{
    if (sr->fd_file > 0) {
        mk_vhost_close(sr);
    }

    if (sr->headers.location) {
        mk_mem_free(sr->headers.location);
    }

    if (sr->uri_processed.data != sr->uri.data) {
        mk_ptr_free(&sr->uri_processed);
    }

    if (sr->real_path.data != sr->real_path_static) {
        mk_ptr_free(&sr->real_path);
    }
}

int mk_request_header_toc_parse(struct headers_toc *toc, const char *data, int len)
{
    int i = 0;
    int header_len;
    int colon;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,7 +99,12 @@
 void mk_request_free(struct session_request *sr)
 {
     if (sr->fd_file > 0) {
-        mk_vhost_close(sr);
+        if (sr->fd_is_fdt == MK_TRUE) {
+            mk_vhost_close(sr);
+        }
+        else {
+            close(sr->fd_file);
+        }
     }
 
     if (sr->headers.location) {
@@ -841,7 +846,8 @@
                 break;
             }
 
-            sr->fd_file = fd;
+            sr->fd_file   = fd;
+            sr->fd_is_fdt = MK_FALSE;
             sr->bytes_to_send = finfo.size;
             sr->headers.content_length = finfo.size;
             sr->headers.real_length    = finfo.size;
```
