# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 903_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `903_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 32-73 of the vulnerable file.

				    IRC_SERVER_CONNECT_REC *src)
{
	IRC_SERVER_CONNECT_REC *rec;

	g_return_if_fail(dest != NULL);
	if (!IS_IRC_SERVER_CONNECT(src))
		return;

	rec = g_new0(IRC_SERVER_CONNECT_REC, 1);
	rec->chat_type = IRC_PROTOCOL;
	rec->max_cmds_at_once = src->max_cmds_at_once;
	rec->cmd_queue_speed = src->cmd_queue_speed;
        rec->max_query_chans = src->max_query_chans;
	rec->max_kicks = src->max_kicks;
	rec->max_modes = src->max_modes;
	rec->max_msgs = src->max_msgs;
	rec->max_whois = src->max_whois;
	rec->usermode = g_strdup(src->usermode);
	rec->alternate_nick = g_strdup(src->alternate_nick);
	rec->sasl_mechanism = src->sasl_mechanism;
	rec->sasl_username = src->sasl_username;
	rec->sasl_password = src->sasl_password;
	*dest = (SERVER_CONNECT_REC *) rec;
}

static void sig_server_reconnect_save_status(IRC_SERVER_CONNECT_REC *conn,
					     IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER_CONNECT(conn) || !IS_IRC_SERVER(server) ||
	    !server->connected)
		return;

	g_free_not_null(conn->channels);
	conn->channels = irc_server_get_channels(server);

	g_free_not_null(conn->usermode);
	conn->usermode = g_strdup(server->wanted_usermode);
}

static void sig_connected(IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server) || !server->connrec->reconnection)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,8 +49,8 @@
 	rec->usermode = g_strdup(src->usermode);
 	rec->alternate_nick = g_strdup(src->alternate_nick);
 	rec->sasl_mechanism = src->sasl_mechanism;
-	rec->sasl_username = src->sasl_username;
-	rec->sasl_password = src->sasl_password;
+	rec->sasl_username = g_strdup(src->sasl_username);
+	rec->sasl_password = g_strdup(src->sasl_password);
 	*dest = (SERVER_CONNECT_REC *) rec;
 }
 
```
