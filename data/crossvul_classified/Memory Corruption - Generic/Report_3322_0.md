# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3322_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3322_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 495-535 of the vulnerable file.

        res = temp;
        free (realname);
    }

    /* return result */
    return res;
}

/*
 * Returns filename for DCC, without double quotes.
 *
 * Note: result must be freed after use.
 */

char *
irc_ctcp_dcc_filename_without_quotes (const char *filename)
{
    int length;

    length = strlen (filename);
    if (length > 0)
    {
        if ((filename[0] == '\"') && (filename[length - 1] == '\"'))
            return weechat_strndup (filename + 1, length - 2);
    }
    return strdup (filename);
}

/*
 * Parses CTCP DCC.
 */

void
irc_ctcp_recv_dcc (struct t_irc_server *server, const char *nick,
                   const char *arguments, char *message)
{
    char *dcc_args, *pos, *pos_file, *pos_addr, *pos_port, *pos_size;
    char *pos_start_resume, *filename;
    struct t_infolist *infolist;
    struct t_infolist_item *item;
    char charset_modifier[256];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -512,7 +512,7 @@
     int length;
 
     length = strlen (filename);
-    if (length > 0)
+    if (length > 1)
     {
         if ((filename[0] == '\"') && (filename[length - 1] == '\"'))
             return weechat_strndup (filename + 1, length - 2);
```
