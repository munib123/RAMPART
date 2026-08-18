# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1567_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1567_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 459-514 of the vulnerable file.

    /* We let the peer know that problem dir was created successfully
     * _before_ we run potentially long-running post-create.
     */
    printf("HTTP/1.1 201 Created\r\n\r\n");
    fflush(NULL);
    close(STDOUT_FILENO);
    xdup2(STDERR_FILENO, STDOUT_FILENO); /* paranoia: don't leave stdout fd closed */

    /* Trim old problem directories if necessary */
    if (g_settings_nMaxCrashReportsSize > 0)
    {
        trim_problem_dirs(g_settings_dump_location, g_settings_nMaxCrashReportsSize * (double)(1024*1024), path);
    }

    run_post_create(path);

    /* free(path); */
    exit(0);
}

/* Checks if a string contains only printable characters. */
static gboolean printable_str(const char *str)
{
    do {
        if ((unsigned char)(*str) < ' ' || *str == 0x7f)
            return FALSE;
        str++;
    } while (*str);
    return TRUE;
}

static gboolean is_correct_filename(const char *value)
{
    return printable_str(value) && !strchr(value, '/') && !strchr(value, '.');
}

static gboolean key_value_ok(gchar *key, gchar *value)
{
    char *i;

    /* check key, it has to be valid filename and will end up in the
     * bugzilla */
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
        if (!is_correct_filename(value))
        {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -476,22 +476,6 @@
     exit(0);
 }
 
-/* Checks if a string contains only printable characters. */
-static gboolean printable_str(const char *str)
-{
-    do {
-        if ((unsigned char)(*str) < ' ' || *str == 0x7f)
-            return FALSE;
-        str++;
-    } while (*str);
-    return TRUE;
-}
-
-static gboolean is_correct_filename(const char *value)
-{
-    return printable_str(value) && !strchr(value, '/') && !strchr(value, '.');
-}
-
 static gboolean key_value_ok(gchar *key, gchar *value)
 {
     char *i;
@@ -510,7 +494,7 @@
      || strcmp(key, FILENAME_TYPE) == 0
     )
     {
-        if (!is_correct_filename(value))
+        if (!str_is_correct_filename(value))
         {
             error_msg("Value of '%s' ('%s') is not a valid directory name",
                       key, value);
```
