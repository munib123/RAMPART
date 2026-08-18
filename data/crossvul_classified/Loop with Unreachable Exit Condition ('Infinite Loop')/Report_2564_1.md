# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2564_1
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2564_1`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 74-114 of the vulnerable file.

};

enum {
        PROP_0,
        PROP_CLIENT_STORE
};

static void     gsm_xsmp_server_class_init  (GsmXsmpServerClass *klass);
static void     gsm_xsmp_server_init        (GsmXsmpServer      *xsmp_server);
static void     gsm_xsmp_server_finalize    (GObject         *object);

static gpointer xsmp_server_object = NULL;

G_DEFINE_TYPE (GsmXsmpServer, gsm_xsmp_server, G_TYPE_OBJECT)

typedef struct {
        GsmXsmpServer *server;
        IceListenObj   listener;
} GsmIceConnectionData;

/* This is called (by glib via xsmp->ice_connection_watch) when a
 * connection is first received on the ICE listening socket. (We
 * expect that the client will then initiate XSMP on the connection;
 * if it does not, GsmXSMPClient will eventually time out and close
 * the connection.)
 *
 * FIXME: it would probably make more sense to not create a
 * GsmXSMPClient object until accept_xsmp_connection, below (and to do
 * the timing-out here in xsmp.c).
 */
static gboolean
accept_ice_connection (GIOChannel           *source,
                       GIOCondition          condition,
                       GsmIceConnectionData *data)
{
        IceListenObj    listener;
        IceConn         ice_conn;
        IceAcceptStatus status;
        GsmClient      *client;
        GsmXsmpServer  *server;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,44 +91,134 @@
         IceListenObj   listener;
 } GsmIceConnectionData;
 
+typedef struct {
+        guint watch_id;
+        guint protocol_timeout;
+} GsmIceConnectionWatch;
+
+static void
+disconnect_ice_connection (IceConn ice_conn)
+{
+        IceSetShutdownNegotiation (ice_conn, FALSE);
+        IceCloseConnection (ice_conn);
+}
+
+static void
+free_ice_connection_watch (GsmIceConnectionWatch *data)
+{
+        if (data->watch_id) {
+                g_source_remove (data->watch_id);
+                data->watch_id = 0;
+        }
+
+        if (data->protocol_timeout) {
+                g_source_remove (data->protocol_timeout);
+                data->protocol_timeout = 0;
+        }
+
+        g_free (data);
+}
+
+static gboolean
+ice_protocol_timeout (IceConn ice_conn)
+{
+        GsmIceConnectionWatch *data;
+
+        g_debug ("GsmXsmpServer: ice_protocol_timeout for IceConn %p with status %d",
+                 ice_conn, IceConnectionStatus (ice_conn));
+
+        data = ice_conn->context;
+
+        free_ice_connection_watch (data);
+        disconnect_ice_connection (ice_conn);
+
+        return FALSE;
+}
+
+static gboolean
+auth_iochannel_watch (GIOChannel   *source,
+                      GIOCondition  condition,
+                      IceConn       ice_conn)
+{
+
+        GsmIceConnectionWatch *data;
+        gboolean               keep_going;
+
+        data = ice_conn->context;
+
+        switch (IceProcessMessages (ice_conn, NULL, NULL)) {
+        case IceProcessMessagesSuccess:
+                keep_going = TRUE;
+                break;
+        case IceProcessMessagesIOError:
+                g_debug ("GsmXsmpServer: IceProcessMessages returned IceProcessMessagesIOError");
+                free_ice_connection_watch (data);
+                disconnect_ice_connection (ice_conn);
+                keep_going = FALSE;
+                break;
+        case IceProcessMessagesConnectionClosed:
+                g_debug ("GsmXsmpServer: IceProcessMessages returned IceProcessMessagesConnectionClosed");
+                free_ice_connection_watch (data);
+                keep_going = FALSE;
+                break;
+        default:
+                g_assert_not_reached ();
+        }
+
+        return keep_going;
+}
+
+/* IceAcceptConnection returns a new ICE connection that is in a "pending" state,
+ * this is because authentification may be necessary.
+ * So we've to authenticate it, before accept_xsmp_connection() is called.
+ * Then each GsmXSMPClient will have its own IceConn watcher
+ */
+static void
+auth_ice_connection (IceConn ice_conn)
+{
+        GIOChannel            *channel;
+        GsmIceConnectionWatch *data;
+        int                    fd;
+
+        g_debug ("GsmXsmpServer: auth_ice_connection()");
+
+        fd = IceConnectionNumber (ice_conn);
+        fcntl (fd, F_SETFD, fcntl (fd, F_GETFD, 0) | FD_CLOEXEC);
+        channel = g_io_channel_unix_new (fd);
+
+        data = g_new0 (GsmIceConnectionWatch, 1);
+        ice_conn->context = data;
+
+        data->protocol_timeout = g_timeout_add_seconds (5,
+                                                        (GSourceFunc)ice_protocol_timeout,
+                                                        ice_conn);
+        data->watch_id = g_io_add_watch (channel,
+                                         G_IO_IN | G_IO_ERR,
+                                         (GIOFunc)auth_iochannel_watch,
+                                         ice_conn);
+        g_io_channel_unref (channel);
+}
+
 /* This is called (by glib via xsmp->ice_connection_watch) when a
- * connection is first received on the ICE listening socket. (We
- * expect that the client will then initiate XSMP on the connection;
- * if it does not, GsmXSMPClient will eventually time out and close
- * the connection.)
- *
- * FIXME: it would probably make more sense to not create a
- * GsmXSMPClient object until accept_xsmp_connection, below (and to do
- * the timing-out here in xsmp.c).
+ * connection is first received on the ICE listening socket.
  */
 static gboolean
 accept_ice_connection (GIOChannel           *source,
                        GIOCondition          condition,
                        GsmIceConnectionData *data)
 {
-        IceListenObj    listener;
         IceConn         ice_conn;
         IceAcceptStatus status;
-        GsmClient      *client;
-        GsmXsmpServer  *server;
-
-        listener = data->listener;
-        server = data->server;
 
         g_debug ("GsmXsmpServer: accept_ice_connection()");
 
-        ice_conn = IceAcceptConnection (listener, &status);
+        ice_conn = IceAcceptConnection (data->listener, &status);
         if (status != IceAcceptSuccess) {
                 g_debug ("GsmXsmpServer: IceAcceptConnection returned %d", status);
                 return TRUE;
         }
 
-        client = gsm_xsmp_client_new (ice_conn);
-        ice_conn->context = client;
-
-        gsm_store_add (server->priv->client_store, gsm_client_peek_id (client), G_OBJECT (client));
-        /* the store will own the ref */
-        g_object_unref (client);
+        auth_ice_connection (ice_conn);
 
         return TRUE;
 }
@@ -224,8 +314,9 @@
                         SmsCallbacks  *callbacks_ret,
                         char         **failure_reason_ret)
 {
-        IceConn        ice_conn;
-        GsmXSMPClient *client;
+        IceConn                ice_conn;
+        GsmClient             *client;
+        GsmIceConnectionWatch *data;
 
         /* FIXME: what about during shutdown but before gsm_xsmp_shutdown? */
         if (server->priv->xsmp_sockets == NULL) {
@@ -236,11 +327,18 @@
         }
 
         ice_conn = SmsGetIceConnection (sms_conn);
-        client = ice_conn->context;
-
-        g_return_val_if_fail (client != NULL, TRUE);
-
-        gsm_xsmp_client_connect (client, sms_conn, mask_ret, callbacks_ret);
+        data = ice_conn->context;
+
+        /* Each GsmXSMPClient has its own IceConn watcher */
+        free_ice_connection_watch (data);
+
+        client = gsm_xsmp_client_new (ice_conn);
+
+        gsm_store_add (server->priv->client_store, gsm_client_peek_id (client), G_OBJECT (client));
+        /* the store will own the ref */
+        g_object_unref (client);
+
+        gsm_xsmp_client_connect (GSM_XSMP_CLIENT (client), sms_conn, mask_ret, callbacks_ret);
 
         return TRUE;
 }
```
