# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5655_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5655_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 332-367 of the vulnerable file.

{
    (void) conx;

    /* Validate ip address with Mandril rules */
    if (mk_security_check_ip(socket) != 0) {
        PLUGIN_TRACE("[FD %i] Mandril close connection", socket);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }
    return MK_PLUGIN_RET_CONTINUE;
}

int _mkp_stage_30(struct plugin *p,
        struct client_session *cs,
        struct session_request *sr)
{
    mk_ptr_t referer;
    (void) p;
    (void) cs;

    PLUGIN_TRACE("[FD %i] Mandril validating URL", cs->socket);
    if (mk_security_check_url(sr->uri) < 0) {
        PLUGIN_TRACE("[FD %i] Close connection, blocked URL", cs->socket);
        mk_api->header_set_http_status(sr, MK_CLIENT_FORBIDDEN);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    PLUGIN_TRACE("[FD %d] Mandril validating hotlinking", cs->socket);
    referer = mk_api->header_get(&sr->headers_toc, "Referer", strlen("Referer"));
    if (mk_security_check_hotlink(sr->uri_processed, sr->host, referer) < 0) {
        PLUGIN_TRACE("[FD %i] Close connection, deny hotlinking.", cs->socket);
        mk_api->header_set_http_status(sr, MK_CLIENT_FORBIDDEN);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    return MK_PLUGIN_RET_NOT_ME;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -349,7 +349,8 @@
     (void) cs;
 
     PLUGIN_TRACE("[FD %i] Mandril validating URL", cs->socket);
-    if (mk_security_check_url(sr->uri) < 0) {
+
+    if (mk_security_check_url(sr->uri_processed) < 0) {
         PLUGIN_TRACE("[FD %i] Close connection, blocked URL", cs->socket);
         mk_api->header_set_http_status(sr, MK_CLIENT_FORBIDDEN);
         return MK_PLUGIN_RET_CLOSE_CONX;
```
