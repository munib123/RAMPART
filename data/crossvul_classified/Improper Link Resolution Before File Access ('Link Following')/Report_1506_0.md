# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1506_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1506_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 470-510 of the vulnerable file.

    for (i = key; *i != 0; i++)
    {
        if (!isalpha(*i) && (*i != '-') && (*i != '_') && (*i != ' '))
            return FALSE;
    }

    /* check value of 'basename', it has to be valid non-hidden directory
     * name */
    if (strcmp(key, "basename") == 0
     || strcmp(key, FILENAME_TYPE) == 0
    )
    {
        if (!str_is_correct_filename(value))
        {
            error_msg("Value of '%s' ('%s') is not a valid directory name",
                      key, value);
            return FALSE;
        }
    }

    return TRUE;
}

/* Handles a message received from client over socket. */
static void process_message(GHashTable *problem_info, char *message)
{
    gchar *key, *value;

    value = strchr(message, '=');
    if (value)
    {
        key = g_ascii_strdown(message, value - message); /* result is malloced */
//TODO: is it ok? it uses g_malloc, not malloc!

        value++;
        if (key_value_ok(key, value))
        {
            if (strcmp(key, FILENAME_UID) == 0)
            {
                error_msg("Ignoring value of %s, will be determined later",
                          FILENAME_UID);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -487,7 +487,7 @@
         }
     }
 
-    return TRUE;
+    return allowed_new_user_problem_entry(client_uid, key, value);
 }
 
 /* Handles a message received from client over socket. */
```
