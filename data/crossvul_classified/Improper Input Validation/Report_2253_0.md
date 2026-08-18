# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2253_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2253_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 142-182 of the vulnerable file.

struct headers_toc
{
    struct header_toc_row rows[MK_HEADERS_TOC_LEN];
    int length;
};

struct session_request
{
    int status;
    int protocol;
    /* is keep-alive request ? */
    int keep_alive;

    /* is it serving a user's home directory ? */
    int user_home;

    /*-Connection-*/
    long port;
    /*------------*/

    /* file descriptors */
    int fd_file;

    int headers_len;

    /*----First header of client request--*/
    int method;
    mk_ptr_t method_p;
    mk_ptr_t uri;                  /* original request */
    mk_ptr_t uri_processed;        /* processed request (decoded) */

    mk_ptr_t protocol_p;

    mk_ptr_t body;





    /* If request specify Connection: close, Monkey will
     * close the connection after send the response, by
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -159,8 +159,18 @@
     long port;
     /*------------*/
 
-    /* file descriptors */
+    /*
+     * Static file file descriptor: the following twp fields represents an
+     * opened file in the file system and a flag saying which mechanism
+     * was used to open it.
+     *
+     *  - fd_file  : common file descriptor
+     *  - fd_is_fdt: set to MK_TRUE if fd_file was opened using Vhost FDT, or
+     *               MK_FALSE for the opposite case.
+     */
     int fd_file;
+    int fd_is_fdt;
+
 
     int headers_len;
 
```
