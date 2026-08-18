# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3453_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3453_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 40-80 of the vulnerable file.


/* 
 * Simple but fast command-line reader. We break the FTP protocol here,
 * because we deny access to files with strange characters in their name.
 * Now, I seriously doubt that clients should be allowed to upload files
 * with carriage returns, bells, cursor moves and other fancy stuff in the
 * names. It can indirectly lead to security flaws with scripts, it's
 * annoying for the sysadmin, it can be a client error, it can bring unexpected
 * results on some filesystems, etc. So control chars are replaced by "_".
 * Better be safe than 100% RFC crap compliant but unsafe. If you really want
 * RFC compliance, define RFC_CONFORMANT_PARSER. But I will hate you.
 * 
 * RFC_CONFORMANT_LINES is another thing that clients should implement
 * properly (and it's trivial to do) : lines must be ended with \r\n .
 * Guess what ? 
 * Some broken clients are just sending \n ... Grrrrrrrrrrrr !!!!!!!!!!!!!!!
 * 
 * -Frank.
 */

int sfgets(void)
{
    struct pollfd pfd;
    int pollret;
    ssize_t readnb;
    signed char seen_r = 0;
    static size_t scanned;
    static size_t readnbd;
    
    if (scanned > (size_t) 0U) {       /* support pipelining */
        readnbd -= scanned;        
        memmove(cmd, cmd + scanned, readnbd);   /* safe */
        scanned = (size_t) 0U;
    }
    pfd.fd = clientfd;
#ifdef __APPLE_CC__
    pfd.events = POLLIN | POLLERR | POLLHUP;
#else
    pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP;
#endif
    while (scanned < cmdsize) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,14 +57,20 @@
  * -Frank.
  */
 
+static size_t scanned;
+static size_t readnbd;
+
+static void flush_cmd(void)
+{
+    scanned = readnbd = (size_t) 0U;
+}
+
 int sfgets(void)
 {
     struct pollfd pfd;
     int pollret;
     ssize_t readnb;
     signed char seen_r = 0;
-    static size_t scanned;
-    static size_t readnbd;
     
     if (scanned > (size_t) 0U) {       /* support pipelining */
         readnbd -= scanned;        
@@ -362,6 +368,7 @@
             addreply_noformat(234, "AUTH TLS OK.");
             doreply();
             if (tls_cnx == NULL) {
+                flush_cmd();
                 (void) tls_init_new_session();
             }
             goto wayout;
```
