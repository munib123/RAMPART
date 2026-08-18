# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4697_2
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4697_2`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 57-97 of the vulnerable file.

                                     struct t_irc_nick *nick,
                                     char prefix_mode);
extern const char *irc_nick_get_prefix_color_name (struct t_irc_server *server,
                                                   char prefix);
extern void irc_nick_nicklist_set_prefix_color_all ();
extern void irc_nick_nicklist_set_color_all ();
extern struct t_irc_nick *irc_nick_new (struct t_irc_server *server,
                                        struct t_irc_channel *channel,
                                        const char *nickname,
                                        const char *host,
                                        const char *prefixes,
                                        int away,
                                        const char *account,
                                        const char *realname);
extern void irc_nick_change (struct t_irc_server *server,
                             struct t_irc_channel *channel,
                             struct t_irc_nick *nick, const char *new_nick);
extern void irc_nick_set_mode (struct t_irc_server *server,
                               struct t_irc_channel *channel,
                               struct t_irc_nick *nick, int set, char mode);
extern void irc_nick_free (struct t_irc_server *server,
                           struct t_irc_channel *channel,
                           struct t_irc_nick *nick);
extern void irc_nick_free_all (struct t_irc_server *server,
                               struct t_irc_channel *channel);
extern struct t_irc_nick *irc_nick_search (struct t_irc_server *server,
                                           struct t_irc_channel *channel,
                                           const char *nickname);
extern void irc_nick_count (struct t_irc_server *server,
                            struct t_irc_channel *channel, int *total,
                            int *count_op, int *count_halfop, int *count_voice,
                            int *count_normal);
extern void irc_nick_set_away (struct t_irc_server *server,
                               struct t_irc_channel *channel,
                               struct t_irc_nick *nick, int is_away);
extern const char *irc_nick_mode_for_display (struct t_irc_server *server,
                                              struct t_irc_nick *nick,
                                              int prefix);
extern const char *irc_nick_as_prefix (struct t_irc_server *server,
                                       struct t_irc_nick *nick,
                                       const char *nickname,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,6 +74,8 @@
 extern void irc_nick_set_mode (struct t_irc_server *server,
                                struct t_irc_channel *channel,
                                struct t_irc_nick *nick, int set, char mode);
+extern void irc_nick_realloc_prefixes (struct t_irc_server *server,
+                                       int old_length, int new_length);
 extern void irc_nick_free (struct t_irc_server *server,
                            struct t_irc_channel *channel,
                            struct t_irc_nick *nick);
```
