# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 903_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `903_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 58-98 of the vulnerable file.

static CHANNEL_SETUP_REC *create_channel_setup(void)
{
        return g_malloc0(sizeof(CHANNEL_SETUP_REC));
}

static SERVER_CONNECT_REC *create_server_connect(void)
{
        return g_malloc0(sizeof(IRC_SERVER_CONNECT_REC));
}

static void destroy_server_connect(SERVER_CONNECT_REC *conn)
{
	IRC_SERVER_CONNECT_REC *ircconn;

        ircconn = IRC_SERVER_CONNECT(conn);
	if (ircconn == NULL)
		return;

	g_free_not_null(ircconn->usermode);
	g_free_not_null(ircconn->alternate_nick);
}

void irc_core_init(void)
{
	CHAT_PROTOCOL_REC *rec;

	rec = g_new0(CHAT_PROTOCOL_REC, 1);
	rec->name = "IRC";
	rec->fullname = "Internet Relay Chat";
	rec->chatnet = "ircnet";

        rec->case_insensitive = TRUE;

	rec->create_chatnet = create_chatnet;
        rec->create_server_setup = create_server_setup;
        rec->create_channel_setup = create_channel_setup;
	rec->create_server_connect = create_server_connect;
	rec->destroy_server_connect = destroy_server_connect;

	rec->server_init_connect = irc_server_init_connect;
	rec->server_connect = irc_server_connect;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,6 +75,8 @@
 
 	g_free_not_null(ircconn->usermode);
 	g_free_not_null(ircconn->alternate_nick);
+	g_free_not_null(ircconn->sasl_username);
+	g_free_not_null(ircconn->sasl_password);
 }
 
 void irc_core_init(void)
```
