# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 903_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `903_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 84-125 of the vulnerable file.

	if (ircnet->max_whois > 0) conn->max_whois = ircnet->max_whois;

	if (ircnet->max_cmds_at_once > 0)
		conn->max_cmds_at_once = ircnet->max_cmds_at_once;
	if (ircnet->cmd_queue_speed > 0)
		conn->cmd_queue_speed = ircnet->cmd_queue_speed;
	if (ircnet->max_query_chans > 0)
		conn->max_query_chans = ircnet->max_query_chans;

	/* Validate the SASL parameters filled by sig_chatnet_read() or cmd_network_add */
	conn->sasl_mechanism = SASL_MECHANISM_NONE;
	conn->sasl_username = NULL;
	conn->sasl_password = NULL;

	if (ircnet->sasl_mechanism != NULL) {
		if (!g_ascii_strcasecmp(ircnet->sasl_mechanism, "plain")) {
			/* The PLAIN method needs both the username and the password */
			conn->sasl_mechanism = SASL_MECHANISM_PLAIN;
			if (ircnet->sasl_username != NULL && *ircnet->sasl_username &&
			    ircnet->sasl_password != NULL && *ircnet->sasl_password) {
				conn->sasl_username = ircnet->sasl_username;
				conn->sasl_password = ircnet->sasl_password;
			} else
				g_warning("The fields sasl_username and sasl_password are either missing or empty");
		}
		else if (!g_ascii_strcasecmp(ircnet->sasl_mechanism, "external")) {
			conn->sasl_mechanism = SASL_MECHANISM_EXTERNAL;
		}
		else
			g_warning("Unsupported SASL mechanism \"%s\" selected", ircnet->sasl_mechanism);
	}
}

static void init_userinfo(void)
{
	unsigned int changed;
	const char *set, *nick, *user_name, *str;

	changed = 0;
	/* check if nick/username/realname wasn't read from setup.. */
        set = settings_get_str("real_name");
	if (set == NULL || *set == '\0') {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,8 +101,8 @@
 			conn->sasl_mechanism = SASL_MECHANISM_PLAIN;
 			if (ircnet->sasl_username != NULL && *ircnet->sasl_username &&
 			    ircnet->sasl_password != NULL && *ircnet->sasl_password) {
-				conn->sasl_username = ircnet->sasl_username;
-				conn->sasl_password = ircnet->sasl_password;
+				conn->sasl_username = g_strdup(ircnet->sasl_username);
+				conn->sasl_password = g_strdup(ircnet->sasl_password);
 			} else
 				g_warning("The fields sasl_username and sasl_password are either missing or empty");
 		}
```
