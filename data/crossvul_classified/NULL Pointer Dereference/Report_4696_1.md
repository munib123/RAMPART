# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4696_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4696_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 4672-4712 of the vulnerable file.


IRC_PROTOCOL_CALLBACK(352)
{
    char *pos_attr, *pos_hopcount, *pos_realname, *str_host;
    int arg_start, length;
    struct t_irc_channel *ptr_channel;
    struct t_irc_nick *ptr_nick;

    IRC_PROTOCOL_MIN_ARGS(5);

    /* silently ignore malformed 352 message (missing infos) */
    if (argc < 8)
        return WEECHAT_RC_OK;

    pos_attr = NULL;
    pos_hopcount = NULL;
    pos_realname = NULL;

    if (argc > 8)
    {
        arg_start = (strcmp (argv[8], "*") == 0) ? 9 : 8;
        if (argv[arg_start][0] == ':')
        {
            pos_attr = NULL;
            pos_hopcount = (argc > arg_start) ? argv[arg_start] + 1 : NULL;
            pos_realname = (argc > arg_start + 1) ? argv_eol[arg_start + 1] : NULL;
        }
        else
        {
            pos_attr = argv[arg_start];
            pos_hopcount = (argc > arg_start + 1) ? argv[arg_start + 1] + 1 : NULL;
            pos_realname = (argc > arg_start + 2) ? argv_eol[arg_start + 2] : NULL;
        }
    }

    ptr_channel = irc_channel_search (server, argv[3]);
    ptr_nick = (ptr_channel) ?
        irc_nick_search (server, ptr_channel, argv[7]) : NULL;

    /* update host in nick */
    if (ptr_nick)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4689,7 +4689,7 @@
 
     if (argc > 8)
     {
-        arg_start = (strcmp (argv[8], "*") == 0) ? 9 : 8;
+        arg_start = ((argc > 9) && (strcmp (argv[8], "*") == 0)) ? 9 : 8;
         if (argv[arg_start][0] == ':')
         {
             pos_attr = NULL;
```
