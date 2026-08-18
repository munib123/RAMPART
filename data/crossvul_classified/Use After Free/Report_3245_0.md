# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3245_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3245_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 453-493 of the vulnerable file.


static void read_settings(void)
{
	int old_hide;

        old_hide = hide_netsplit_quits;
	hide_netsplit_quits = settings_get_bool("hide_netsplit_quits");
	netjoin_max_nicks = settings_get_int("netjoin_max_nicks");

	if (old_hide && !hide_netsplit_quits) {
		signal_remove("message quit", (SIGNAL_FUNC) msg_quit);
		signal_remove("message join", (SIGNAL_FUNC) msg_join);
		signal_remove("message irc mode", (SIGNAL_FUNC) msg_mode);
	} else if (!old_hide && hide_netsplit_quits) {
		signal_add("message quit", (SIGNAL_FUNC) msg_quit);
		signal_add("message join", (SIGNAL_FUNC) msg_join);
		signal_add("message irc mode", (SIGNAL_FUNC) msg_mode);
	}
}

void fe_netjoin_init(void)
{
	settings_add_bool("misc", "hide_netsplit_quits", TRUE);
	settings_add_int("misc", "netjoin_max_nicks", 10);

	join_tag = -1;
	printing_joins = FALSE;

	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void fe_netjoin_deinit(void)
{
	while (joinservers != NULL)
		netjoin_server_remove(joinservers->data);
	if (join_tag != -1) {
		g_source_remove(join_tag);
		signal_remove("print starting", (SIGNAL_FUNC) sig_print_starting);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -470,6 +470,20 @@
 	}
 }
 
+static void sig_server_disconnected(IRC_SERVER_REC *server)
+{
+	NETJOIN_SERVER_REC *netjoin_server;
+
+	g_return_if_fail(server != NULL);
+
+	if (!IS_IRC_SERVER(server))
+		return;
+
+	if ((netjoin_server = netjoin_find_server(server))) {
+		netjoin_server_remove(netjoin_server);
+	}
+}
+
 void fe_netjoin_init(void)
 {
 	settings_add_bool("misc", "hide_netsplit_quits", TRUE);
@@ -480,6 +494,7 @@
 
 	read_settings();
 	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
+	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
 }
 
 void fe_netjoin_deinit(void)
@@ -492,6 +507,7 @@
 	}
 
 	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
+	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
 
 	signal_remove("message quit", (SIGNAL_FUNC) msg_quit);
 	signal_remove("message join", (SIGNAL_FUNC) msg_join);
```
