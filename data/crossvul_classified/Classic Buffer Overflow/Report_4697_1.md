# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4697_1
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4697_1`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 627-667 of the vulnerable file.


    /* remove nick from nicklist */
    irc_nick_nicklist_remove (server, channel, nick);

    /* set flag */
    prefix_chars = irc_server_get_prefix_chars (server);
    irc_nick_set_prefix (server, nick, set, prefix_chars[index]);

    /* add nick in nicklist */
    irc_nick_nicklist_add (server, channel, nick);

    if (irc_server_strcasecmp (server, nick->name, server->nick) == 0)
    {
        weechat_bar_item_update ("input_prompt");
        weechat_bar_item_update ("irc_nick");
        weechat_bar_item_update ("irc_nick_host");
    }
}

/*
 * Removes a nick from a channel.
 */

void
irc_nick_free (struct t_irc_server *server, struct t_irc_channel *channel,
               struct t_irc_nick *nick)
{
    struct t_irc_nick *new_nicks;

    if (!channel || !nick)
        return;

    /* remove nick from nicklist */
    irc_nick_nicklist_remove (server, channel, nick);

    /* remove nick */
    if (channel->last_nick == nick)
        channel->last_nick = nick->prev_nick;
    if (nick->prev_nick)
    {
        (nick->prev_nick)->next_nick = nick->next_nick;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -640,6 +640,53 @@
         weechat_bar_item_update ("input_prompt");
         weechat_bar_item_update ("irc_nick");
         weechat_bar_item_update ("irc_nick_host");
+    }
+}
+
+/*
+ * Reallocates the "prefixes" string in all nicks of all channels on the server
+ * (after 005 has been received).
+ */
+
+void
+irc_nick_realloc_prefixes (struct t_irc_server *server,
+                           int old_length, int new_length)
+{
+    struct t_irc_channel *ptr_channel;
+    struct t_irc_nick *ptr_nick;
+    char *new_prefixes;
+
+    for (ptr_channel = server->channels; ptr_channel;
+         ptr_channel = ptr_channel->next_channel)
+    {
+        for (ptr_nick = ptr_channel->nicks; ptr_nick;
+             ptr_nick = ptr_nick->next_nick)
+        {
+            if (ptr_nick->prefixes)
+            {
+                new_prefixes = realloc (ptr_nick->prefixes, new_length + 1);
+                if (new_prefixes)
+                {
+                    ptr_nick->prefixes = new_prefixes;
+                    if (new_length > old_length)
+                    {
+                        memset (ptr_nick->prefixes + old_length,
+                                ' ',
+                                new_length - old_length);
+                    }
+                    ptr_nick->prefixes[new_length] = '\0';
+                }
+            }
+            else
+            {
+                ptr_nick->prefixes = malloc (new_length + 1);
+                if (ptr_nick->prefixes)
+                {
+                    memset (ptr_nick->prefixes, ' ', new_length);
+                    ptr_nick->prefixes[new_length] = '\0';
+                }
+            }
+        }
     }
 }
 
```
