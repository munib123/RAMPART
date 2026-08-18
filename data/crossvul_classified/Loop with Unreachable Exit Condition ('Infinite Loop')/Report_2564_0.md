# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2564_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2564_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 34-74 of the vulnerable file.

#include "gsm-xsmp-client.h"
#include "gsm-marshal.h"

#include "gsm-util.h"
#include "gsm-autostart-app.h"
#include "gsm-manager.h"

#define GsmDesktopFile "_GSM_DesktopFile"

#define IS_STRING_EMPTY(x) ((x)==NULL||(x)[0]=='\0')

#define GSM_XSMP_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), GSM_TYPE_XSMP_CLIENT, GsmXSMPClientPrivate))

struct GsmXSMPClientPrivate
{

        SmsConn    conn;
        IceConn    ice_connection;

        guint      watch_id;
        guint      protocol_timeout;

        char      *description;
        GPtrArray *props;

        /* SaveYourself state */
        int        current_save_yourself;
        int        next_save_yourself;
        guint      next_save_yourself_allow_interact : 1;
};

enum {
        PROP_0,
        PROP_ICE_CONNECTION
};

enum {
        REGISTER_REQUEST,
        LOGOUT_REQUEST,
        LAST_SIGNAL
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,6 @@
         IceConn    ice_connection;
 
         guint      watch_id;
-        guint      protocol_timeout;
 
         char      *description;
         GPtrArray *props;
@@ -113,22 +112,6 @@
         g_object_unref (client);
 
         return keep_going;
-}
-
-/* Called if too much time passes between the initial connection and
- * the XSMP protocol setup.
- */
-static gboolean
-_client_protocol_timeout (GsmXSMPClient *client)
-{
-        g_debug ("GsmXSMPClient: client_protocol_timeout for client '%s' in ICE status %d",
-                 client->priv->description,
-                 IceConnectionStatus (client->priv->ice_connection));
-
-        gsm_client_set_status (GSM_CLIENT (client), GSM_CLIENT_FAILED);
-        gsm_client_disconnected (GSM_CLIENT (client));
-
-        return FALSE;
 }
 
 static SmProp *
@@ -192,10 +175,6 @@
                                                  (GIOFunc)client_iochannel_watch,
                                                  client);
         g_io_channel_unref (channel);
-
-        client->priv->protocol_timeout = g_timeout_add_seconds (5,
-                                                                (GSourceFunc)_client_protocol_timeout,
-                                                                client);
 
         set_description (client);
 
@@ -868,10 +847,6 @@
         if (client->priv->ice_connection != NULL) {
                 IceSetShutdownNegotiation (client->priv->ice_connection, FALSE);
                 IceCloseConnection (client->priv->ice_connection);
-        }
-
-        if (client->priv->protocol_timeout > 0) {
-                g_source_remove (client->priv->protocol_timeout);
         }
 }
 
@@ -1305,11 +1280,6 @@
 {
         client->priv->conn = conn;
 
-        if (client->priv->protocol_timeout) {
-                g_source_remove (client->priv->protocol_timeout);
-                client->priv->protocol_timeout = 0;
-        }
-
         g_debug ("GsmXSMPClient: Initializing client %s", client->priv->description);
 
         *mask_ret = 0;
```
