# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in c
**Pair ID:** 1353_0
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1353_0`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```c
Lines 606-646 of the vulnerable file.


        if (err_page->value.lengths) {
            ngx_http_split_args(r, &uri, &args);

        } else {
            args = err_page->args;
        }

        if (r->method != NGX_HTTP_HEAD) {
            r->method = NGX_HTTP_GET;
            r->method_name = ngx_http_core_get_method;
        }

        return ngx_http_internal_redirect(r, &uri, &args);
    }

    if (uri.len && uri.data[0] == '@') {
        return ngx_http_named_location(r, &uri);
    }

    location = ngx_list_push(&r->headers_out.headers);

    if (location == NULL) {
        return NGX_ERROR;
    }

    if (overwrite != NGX_HTTP_MOVED_PERMANENTLY
        && overwrite != NGX_HTTP_MOVED_TEMPORARILY
        && overwrite != NGX_HTTP_SEE_OTHER
        && overwrite != NGX_HTTP_TEMPORARY_REDIRECT
        && overwrite != NGX_HTTP_PERMANENT_REDIRECT)
    {
        r->err_status = NGX_HTTP_MOVED_TEMPORARILY;
    }

    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    location->value = uri;

    ngx_http_clear_location(r);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -623,6 +623,12 @@
         return ngx_http_named_location(r, &uri);
     }
 
+    r->expect_tested = 1;
+
+    if (ngx_http_discard_request_body(r) != NGX_OK) {
+        r->keepalive = 0;
+    }
+
     location = ngx_list_push(&r->headers_out.headers);
 
     if (location == NULL) {
```
