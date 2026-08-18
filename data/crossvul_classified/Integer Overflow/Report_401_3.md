# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 401_3
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `401_3`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 112-152 of the vulnerable file.

    info->request->method = parser->method;

    dict_entry *entry;
    dict_iterator *iter = dict_get_iterator(info->request->headers);
    while ((entry = dict_next(iter)) != NULL) {
        log_trace("Header: %s: %s", (char *)entry->key, (char *)entry->val);
    }
    dict_release_iterator(iter);

    if (info->request->method != HTTP_GET)
        goto error;
    if (http_request_get_header(info->request, "Host") == NULL)
        goto error;
    double version = info->request->version_major + info->request->version_minor * 0.1;
    if (version < 1.1)
        goto error;
    const char *upgrade = http_request_get_header(info->request, "Upgrade");
    if (upgrade == NULL || strcasecmp(upgrade, "websocket") != 0)
        goto error;
    const char *connection = http_request_get_header(info->request, "Connection");
    if (connection == NULL)
        goto error;
    else {
        bool found_upgrade = false;
        int count;
        sds *tokens = sdssplitlen(connection, strlen(connection), ",", 1, &count); 
        if (tokens == NULL)
            goto error;
        for (int i = 0; i < count; i++) {
            sds token = tokens[i];
            sdstrim(token, " ");
            if (strcasecmp(token, "Upgrade") == 0) {
                found_upgrade = true;
                break;
            }
        }
        sdsfreesplitres(tokens, count);
        if (!found_upgrade)
            goto error;
    }
    const char *ws_version = http_request_get_header(info->request, "Sec-WebSocket-Version");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -129,7 +129,7 @@
     if (upgrade == NULL || strcasecmp(upgrade, "websocket") != 0)
         goto error;
     const char *connection = http_request_get_header(info->request, "Connection");
-    if (connection == NULL)
+    if (connection == NULL || strlen(connection) > UT_WS_SVR_MAX_HEADER_SIZE)
         goto error;
     else {
         bool found_upgrade = false;
```
