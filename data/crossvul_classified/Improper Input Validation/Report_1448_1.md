# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1448_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1448_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2210-2250 of the vulnerable file.

    request_rec *r = ap_lua_check_request_rec(L, 1);
    
    brigade = apr_brigade_create(r->connection->pool, 
            r->connection->bucket_alloc);
    rv = ap_get_brigade(r->connection->input_filters, brigade, 
            AP_MODE_READBYTES, APR_NONBLOCK_READ, 1);
    if (rv == APR_SUCCESS) {
        lua_pushboolean(L, 1);
    }
    else {
        lua_pushboolean(L, 0);
    }
    apr_brigade_cleanup(brigade);
    return 1;
}

static int lua_websocket_read(lua_State *L) 
{
    apr_socket_t *sock;
    apr_status_t rv;
    int n = 0;
    apr_size_t len = 1;
    apr_size_t plen = 0;
    unsigned short payload_short = 0;
    apr_uint64_t payload_long = 0;
    unsigned char *mask_bytes;
    char byte;
    int plaintext;
    
    
    request_rec *r = ap_lua_check_request_rec(L, 1);
    plaintext = ap_lua_ssl_is_https(r->connection) ? 0 : 1;

    
    mask_bytes = apr_pcalloc(r->pool, 4);
    sock = ap_get_conn_socket(r->connection);

    /* Get opcode and FIN bit */
    if (plaintext) {
        rv = apr_socket_recv(sock, &byte, &len);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2227,6 +2227,7 @@
 {
     apr_socket_t *sock;
     apr_status_t rv;
+    int do_read = 1;
     int n = 0;
     apr_size_t len = 1;
     apr_size_t plen = 0;
@@ -2244,6 +2245,8 @@
     mask_bytes = apr_pcalloc(r->pool, 4);
     sock = ap_get_conn_socket(r->connection);
 
+    while (do_read) { 
+    do_read = 0;
     /* Get opcode and FIN bit */
     if (plaintext) {
         rv = apr_socket_recv(sock, &byte, &len);
@@ -2377,9 +2380,10 @@
                 frame[0] = 0x8A;
                 frame[1] = 0;
                 apr_socket_send(sock, frame, &plen); /* Pong! */
-                lua_websocket_read(L); /* read the next frame instead */
+                do_read = 1;
             }
         }
+    }
     }
     return 0;
 }
```
