# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5786_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5786_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 280-320 of the vulnerable file.

    char *comma = NULL;
    apr_table_entry_t *te;
    int i;

    /* Register TX cleanup */
    apr_pool_cleanup_register(msr->mp, msr, modsecurity_tx_cleanup, apr_pool_cleanup_null);

    /* Initialise C-L */
    msr->request_content_length = -1;
    s = apr_table_get(msr->request_headers, "Content-Length");
    if (s != NULL) {
        msr->request_content_length = strtol(s, NULL, 10);
    }

    /* Figure out whether this request has a body */
    msr->reqbody_chunked = 0;
    msr->reqbody_should_exist = 0;
    if (msr->request_content_length == -1) {
        /* There's no C-L, but is chunked encoding used? */
        char *transfer_encoding = (char *)apr_table_get(msr->request_headers, "Transfer-Encoding");
        if ((transfer_encoding != NULL)&&(strstr(transfer_encoding, "chunked") != NULL)) {
            msr->reqbody_should_exist = 1;
            msr->reqbody_chunked = 1;
        }
    } else {
        /* C-L found */
        msr->reqbody_should_exist = 1;
    }

    /* Initialise C-T */
    msr->request_content_type = NULL;
    s = apr_table_get(msr->request_headers, "Content-Type");
    if (s != NULL) msr->request_content_type = s;

    /* Decide what to do with the request body. */
    if ((msr->request_content_type != NULL)
       && (strncasecmp(msr->request_content_type, "application/x-www-form-urlencoded", 33) == 0))
    {
        /* Always place POST requests with
         * "application/x-www-form-urlencoded" payloads in memory.
         */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -297,7 +297,7 @@
     if (msr->request_content_length == -1) {
         /* There's no C-L, but is chunked encoding used? */
         char *transfer_encoding = (char *)apr_table_get(msr->request_headers, "Transfer-Encoding");
-        if ((transfer_encoding != NULL)&&(strstr(transfer_encoding, "chunked") != NULL)) {
+        if ((transfer_encoding != NULL)&&(m_strcasestr(transfer_encoding, "chunked") != NULL)) {
             msr->reqbody_should_exist = 1;
             msr->reqbody_chunked = 1;
         }
```
