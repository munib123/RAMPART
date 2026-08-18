# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4697_3
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4697_3`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 971-1011 of the vulnerable file.

    }

    /* feature not found in isupport */
    return NULL;
}

/*
 * Sets "prefix_modes" and "prefix_chars" in server using value of PREFIX in IRC
 * message 005.
 *
 * For example, if prefix is "(ohv)@%+":
 *   prefix_modes is set to "ohv"
 *   prefix_chars is set to "@%+".
 */

void
irc_server_set_prefix_modes_chars (struct t_irc_server *server,
                                   const char *prefix)
{
    char *pos;
    int i, length_modes, length_chars;

    if (!server || !prefix)
        return;

    /* free previous values */
    if (server->prefix_modes)
    {
        free (server->prefix_modes);
        server->prefix_modes = NULL;
    }
    if (server->prefix_chars)
    {
        free (server->prefix_chars);
        server->prefix_chars = NULL;
    }

    /* assign new values */
    pos = strchr (prefix, ')');
    if (pos)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -988,10 +988,13 @@
                                    const char *prefix)
 {
     char *pos;
-    int i, length_modes, length_chars;
+    int i, old_length_chars, length_modes, length_chars;
 
     if (!server || !prefix)
         return;
+
+    old_length_chars = (server->prefix_chars) ?
+        strlen (server->prefix_chars) : 0;
 
     /* free previous values */
     if (server->prefix_modes)
@@ -1032,6 +1035,10 @@
             }
         }
     }
+
+    length_chars = (server->prefix_chars) ? strlen (server->prefix_chars) : 0;
+    if (server->prefix_chars && (length_chars != old_length_chars))
+        irc_nick_realloc_prefixes (server, old_length_chars, length_chars);
 }
 
 /*
```
