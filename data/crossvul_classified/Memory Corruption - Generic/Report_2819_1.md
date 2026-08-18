# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2819_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2819_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 278-319 of the vulnerable file.

        && weechat_config_string (logger_config_file_mask)[0])
        return weechat_config_string (logger_config_file_mask);

    /* no default mask set */
    return NULL;
}

/*
 * Gets expanded mask for a buffer.
 *
 * Special vars are replaced:
 *   - local variables of buffer ($plugin, $name, ..)
 *   - date/time specifiers (see man strftime)
 *
 * Note: result must be freed after use.
 */

char *
logger_get_mask_expanded (struct t_gui_buffer *buffer, const char *mask)
{
    char *mask2, *mask_decoded, *mask_decoded2, *mask_decoded3, *mask_decoded4;
    char *mask_decoded5;
    const char *dir_separator;
    int length;
    time_t seconds;
    struct tm *date_tmp;

    mask2 = NULL;
    mask_decoded = NULL;
    mask_decoded2 = NULL;
    mask_decoded3 = NULL;
    mask_decoded4 = NULL;
    mask_decoded5 = NULL;

    dir_separator = weechat_info_get ("dir_separator", "");
    if (!dir_separator)
        return NULL;

    /*
     * we first replace directory separator (commonly '/') by \01 because
     * buffer mask can contain this char, and will be replaced by replacement
     * char ('_' by default)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -295,71 +295,71 @@
 char *
 logger_get_mask_expanded (struct t_gui_buffer *buffer, const char *mask)
 {
-    char *mask2, *mask_decoded, *mask_decoded2, *mask_decoded3, *mask_decoded4;
-    char *mask_decoded5;
+    char *mask2, *mask3, *mask4, *mask5, *mask6, *mask7;
     const char *dir_separator;
     int length;
     time_t seconds;
     struct tm *date_tmp;
 
     mask2 = NULL;
-    mask_decoded = NULL;
-    mask_decoded2 = NULL;
-    mask_decoded3 = NULL;
-    mask_decoded4 = NULL;
-    mask_decoded5 = NULL;
+    mask3 = NULL;
+    mask4 = NULL;
+    mask5 = NULL;
+    mask6 = NULL;
+    mask7 = NULL;
 
     dir_separator = weechat_info_get ("dir_separator", "");
     if (!dir_separator)
         return NULL;
+
+    /* replace date/time specifiers in mask */
+    length = strlen (mask) + 256 + 1;
+    mask2 = malloc (length);
+    if (!mask2)
+        goto end;
+    seconds = time (NULL);
+    date_tmp = localtime (&seconds);
+    mask2[0] = '\0';
+    if (strftime (mask2, length - 1, mask, date_tmp) == 0)
+        mask2[0] = '\0';
 
     /*
      * we first replace directory separator (commonly '/') by \01 because
      * buffer mask can contain this char, and will be replaced by replacement
      * char ('_' by default)
      */
-    mask2 = weechat_string_replace (mask, dir_separator, "\01");
-    if (!mask2)
+    mask3 = weechat_string_replace (mask2, dir_separator, "\01");
+    if (!mask3)
         goto end;
 
-    mask_decoded = weechat_buffer_string_replace_local_var (buffer, mask2);
-    if (!mask_decoded)
+    mask4 = weechat_buffer_string_replace_local_var (buffer, mask3);
+    if (!mask4)
         goto end;
 
-    mask_decoded2 = weechat_string_replace (mask_decoded,
-                                            dir_separator,
-                                            weechat_config_string (logger_config_file_replacement_char));
-    if (!mask_decoded2)
+    mask5 = weechat_string_replace (mask4,
+                                    dir_separator,
+                                    weechat_config_string (logger_config_file_replacement_char));
+    if (!mask5)
         goto end;
 
 #ifdef __CYGWIN__
-    mask_decoded3 = weechat_string_replace (mask_decoded2, "\\",
-                                            weechat_config_string (logger_config_file_replacement_char));
+    mask6 = weechat_string_replace (mask5, "\\",
+                                    weechat_config_string (logger_config_file_replacement_char));
 #else
-    mask_decoded3 = strdup (mask_decoded2);
+    mask6 = strdup (mask5);
 #endif /* __CYGWIN__ */
-    if (!mask_decoded3)
+    if (!mask6)
         goto end;
 
     /* restore directory separator */
-    mask_decoded4 = weechat_string_replace (mask_decoded3,
-                                            "\01", dir_separator);
-    if (!mask_decoded4)
+    mask7 = weechat_string_replace (mask6,
+                                    "\01", dir_separator);
+    if (!mask7)
         goto end;
-
-    /* replace date/time specifiers in mask */
-    length = strlen (mask_decoded4) + 256 + 1;
-    mask_decoded5 = malloc (length);
-    if (!mask_decoded5)
-        goto end;
-    seconds = time (NULL);
-    date_tmp = localtime (&seconds);
-    mask_decoded5[0] = '\0';
-    strftime (mask_decoded5, length - 1, mask_decoded4, date_tmp);
 
     /* convert to lower case? */
     if (weechat_config_boolean (logger_config_file_name_lower_case))
-        weechat_string_tolower (mask_decoded5);
+        weechat_string_tolower (mask7);
 
     if (weechat_logger_plugin->debug)
     {
@@ -368,22 +368,22 @@
                                   "decoded mask = \"%s\"",
                                   LOGGER_PLUGIN_NAME,
                                   weechat_buffer_get_string (buffer, "name"),
-                                  mask, mask_decoded5);
+                                  mask, mask7);
     }
 
 end:
     if (mask2)
         free (mask2);
-    if (mask_decoded)
-        free (mask_decoded);
-    if (mask_decoded2)
-        free (mask_decoded2);
-    if (mask_decoded3)
-        free (mask_decoded3);
-    if (mask_decoded4)
-        free (mask_decoded4);
-
-    return mask_decoded5;
+    if (mask3)
+        free (mask3);
+    if (mask4)
+        free (mask4);
+    if (mask5)
+        free (mask5);
+    if (mask6)
+        free (mask6);
+
+    return mask7;
 }
 
 /*
```
