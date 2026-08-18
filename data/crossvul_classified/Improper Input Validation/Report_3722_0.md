# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3722_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3722_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1644-1684 of the vulnerable file.


    attr = nad_find_attr(nad, 0, -1, "from", NULL);
    if(attr < 0 || (from = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid from on db result packet");
        nad_free(nad);
        return;
    }

    attr = nad_find_attr(nad, 0, -1, "to", NULL);
    if(attr < 0 || (to = jid_new(NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr))) == NULL) {
        log_debug(ZONE, "missing or invalid to on db result packet");
        jid_free(from);
        nad_free(nad);
        return;
    }

    rkey = s2s_route_key(NULL, to->domain, from->domain);
    rkeylen = strlen(rkey);

    /* key is valid */
    if(nad_find_attr(nad, 0, -1, "type", "valid") >= 0) {
        log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] outgoing route '%s' is now valid%s%s", out->fd->fd, out->ip, out->port, rkey, (out->s->flags & SX_SSL_WRAPPER) ? ", TLS negotiated" : "", out->s->compressed ? ", ZLIB compression enabled" : "");

        xhash_put(out->states, pstrdup(xhash_pool(out->states), rkey), (void *) conn_VALID);    /* !!! small leak here */

        log_debug(ZONE, "%s valid, flushing queue", rkey);

        /* flush the queue */
        out_flush_route_queue(out->s2s, rkey, rkeylen);

        free(rkey);

        jid_free(from);
        jid_free(to);

        nad_free(nad);

        return;
    }

    /* invalid */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1661,7 +1661,7 @@
     rkeylen = strlen(rkey);
 
     /* key is valid */
-    if(nad_find_attr(nad, 0, -1, "type", "valid") >= 0) {
+    if(nad_find_attr(nad, 0, -1, "type", "valid") >= 0 && xhash_get(out->states, rkey) == (void*) conn_INPROGRESS) {
         log_write(out->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] outgoing route '%s' is now valid%s%s", out->fd->fd, out->ip, out->port, rkey, (out->s->flags & SX_SSL_WRAPPER) ? ", TLS negotiated" : "", out->s->compressed ? ", ZLIB compression enabled" : "");
 
         xhash_put(out->states, pstrdup(xhash_pool(out->states), rkey), (void *) conn_VALID);    /* !!! small leak here */
@@ -1749,7 +1749,7 @@
     rkey = s2s_route_key(NULL, to->domain, from->domain);
 
     attr = nad_find_attr(nad, 0, -1, "type", "valid");
-    if(attr >= 0) {
+    if(attr >= 0 && xhash_get(in->states, rkey) == (void*) conn_INPROGRESS) {
         xhash_put(in->states, pstrdup(xhash_pool(in->states), rkey), (void *) conn_VALID);
         log_write(in->s2s->log, LOG_NOTICE, "[%d] [%s, port=%d] incoming route '%s' is now valid%s%s", in->fd->fd, in->ip, in->port, rkey, (in->s->flags & SX_SSL_WRAPPER) ? ", TLS negotiated" : "", in->s->compressed ? ", ZLIB compression enabled" : "");
         valid = 1;
```
