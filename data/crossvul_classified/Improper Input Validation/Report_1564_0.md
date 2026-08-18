# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1564_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1564_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 59-112 of the vulnerable file.

   string
   \0
-> "ANALYZER="
   string
   \0
-> "BASENAME="
   string (no slashes)
   \0
-> "REASON="
   string
   \0

You can send more messages using the same KEY=value format.
*/

static unsigned total_bytes_read = 0;

static uid_t client_uid = (uid_t)-1L;


static bool dir_is_in_dump_location(const char *dump_dir_name)
{
    unsigned len = strlen(g_settings_dump_location);

    if (strncmp(dump_dir_name, g_settings_dump_location, len) == 0
     && dump_dir_name[len] == '/'
    /* must not contain "/." anywhere (IOW: disallow ".." component) */
     && !strstr(dump_dir_name + len, "/.")
    ) {
        return 1;
    }
    return 0;
}

/* Remove dump dir */
static int delete_path(const char *dump_dir_name)
{
    /* If doesn't start with "g_settings_dump_location/"... */
    if (!dir_is_in_dump_location(dump_dir_name))
    {
        /* Then refuse to operate on it (someone is attacking us??) */
        error_msg("Bad problem directory name '%s', should start with: '%s'", dump_dir_name, g_settings_dump_location);
        return 400; /* Bad Request */
    }
    if (!dump_dir_accessible_by_uid(dump_dir_name, client_uid))
    {
        if (errno == ENOTDIR)
        {
            error_msg("Path '%s' isn't problem directory", dump_dir_name);
            return 404; /* Not Found */
        }
        error_msg("Problem directory '%s' can't be accessed by user with uid %ld", dump_dir_name, (long)client_uid);
        return 403; /* Forbidden */
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -76,20 +76,6 @@
 static uid_t client_uid = (uid_t)-1L;
 
 
-static bool dir_is_in_dump_location(const char *dump_dir_name)
-{
-    unsigned len = strlen(g_settings_dump_location);
-
-    if (strncmp(dump_dir_name, g_settings_dump_location, len) == 0
-     && dump_dir_name[len] == '/'
-    /* must not contain "/." anywhere (IOW: disallow ".." component) */
-     && !strstr(dump_dir_name + len, "/.")
-    ) {
-        return 1;
-    }
-    return 0;
-}
-
 /* Remove dump dir */
 static int delete_path(const char *dump_dir_name)
 {
@@ -99,6 +85,11 @@
         /* Then refuse to operate on it (someone is attacking us??) */
         error_msg("Bad problem directory name '%s', should start with: '%s'", dump_dir_name, g_settings_dump_location);
         return 400; /* Bad Request */
+    }
+    if (!dir_has_correct_permissions(dump_dir_name))
+    {
+        error_msg("Problem directory '%s' isn't owned by root:abrt or others are not restricted from access", dump_dir_name);
+        return 400; /*  */
     }
     if (!dump_dir_accessible_by_uid(dump_dir_name, client_uid))
     {
@@ -154,26 +145,13 @@
         error_msg("Bad problem directory name '%s', should start with: '%s'", dirname, g_settings_dump_location);
         return 400; /* Bad Request */
     }
+    if (!dir_has_correct_permissions(dirname))
+    {
+        error_msg("Problem directory '%s' isn't owned by root:abrt or others are not restricted from access", dirname);
+        return 400; /*  */
+    }
     if (g_settings_privatereports)
     {
-        struct stat statbuf;
-        if (lstat(dirname, &statbuf) != 0 || !S_ISDIR(statbuf.st_mode))
-        {
-            error_msg("Path '%s' isn't directory", dirname);
-            return 404; /* Not Found */
-        }
-        /* Get ABRT's group gid */
-        struct group *gr = getgrnam("abrt");
-        if (!gr)
-        {
-            error_msg("Group 'abrt' does not exist");
-            return 500;
-        }
-        if (statbuf.st_uid != 0 || !(statbuf.st_gid == 0 || statbuf.st_gid == gr->gr_gid) || statbuf.st_mode & 07)
-        {
-            error_msg("Problem directory '%s' isn't owned by root:abrt or others are not restricted from access", dirname);
-            return 403;
-        }
         struct dump_dir *dd = dd_opendir(dirname, DD_OPEN_READONLY);
         const bool complete = dd && problem_dump_dir_is_complete(dd);
         dd_close(dd);
```
