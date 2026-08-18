# CrossVul Fix Pair: 7PK in c
**Pair ID:** 5328_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5328_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 62-102 of the vulnerable file.

        int rc = 0;

        /* Muliple calls to handshake will be required, this callback
         * will be invoked once the client sends more handshake data. */
        do {
            rc = gnutls_handshake(*client->remote->tls_session);

            if (rc < 0 && rc != GNUTLS_E_AGAIN) {
                crm_err("Remote lrmd tls handshake failed");
                return -1;
            }
        } while (rc == GNUTLS_E_INTERRUPTED);

        if (rc == 0) {
            crm_debug("Remote lrmd tls handshake completed");
            client->remote->tls_handshake_complete = TRUE;
            if (client->remote->auth_timeout) {
                g_source_remove(client->remote->auth_timeout);
            }
            client->remote->auth_timeout = 0;
        }
        return 0;
    }

    rc = crm_remote_ready(client->remote, 0);
    if (rc == 0) {
        /* no msg to read */
        return 0;
    } else if (rc < 0) {
        crm_info("Client disconnected during remote client read");
        return -1;
    }

    crm_remote_recv(client->remote, -1, &disconnected);

    request = crm_remote_parse_buffer(client->remote);
    while (request) {
        crm_element_value_int(request, F_LRMD_REMOTE_MSG_ID, &id);
        crm_trace("processing request from remote client with remote msg id %d", id);
        if (!client->name) {
            const char *value = crm_element_value(request, F_LRMD_CLIENTNAME);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -79,6 +79,9 @@
                 g_source_remove(client->remote->auth_timeout);
             }
             client->remote->auth_timeout = 0;
+
+            /* Alert other clients of the new connection */
+            notify_of_new_client(client);
         }
         return 0;
     }
@@ -289,8 +292,6 @@
                         &lrmd_remote_fd_cb);
     g_hash_table_insert(client_connections, new_client->id, new_client);
 
-    /* Alert other clients of the new connection */
-    notify_of_new_client(new_client);
     return TRUE;
 }
 
```
