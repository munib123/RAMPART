# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1506_3
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1506_3`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 466-485 of the vulnerable file.

    if (g_settings_privatereports)
    {
        struct stat statbuf;
        if (lstat(dir_name, &statbuf) != 0 || !S_ISDIR(statbuf.st_mode))
        {
            error_msg("Path '%s' isn't directory", dir_name);
            return false;
        }
        /* Get ABRT's group gid */
        struct group *gr = getgrnam("abrt");
        if (!gr)
        {
            error_msg("Group 'abrt' does not exist");
            return false;
        }
        if (statbuf.st_uid != 0 || !(statbuf.st_gid == 0 || statbuf.st_gid == gr->gr_gid) || statbuf.st_mode & 07)
            return false;
    }
    return true;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -483,3 +483,27 @@
     }
     return true;
 }
+
+bool allowed_new_user_problem_entry(uid_t uid, const char *name, const char *value)
+{
+    /* Allow root to create everything */
+    if (uid == 0)
+        return true;
+
+    /* Permit non-root users to create everything except: analyzer and type */
+    if (strcmp(name, FILENAME_ANALYZER) != 0
+     && strcmp(name, FILENAME_TYPE) != 0
+     /* compatibility value used in abrt-server */
+     && strcmp(name, "basename") != 0)
+        return true;
+
+    /* Permit non-root users to create all types except: C/C++, Koops, vmcore and xorg */
+     if (strcmp(value, "CCpp") != 0
+      && strcmp(value, "Kerneloops") != 0
+      && strcmp(value, "vmcore") != 0
+      && strcmp(value, "xorg") != 0)
+        return true;
+
+    error_msg("Only root is permitted to create element '%s' containing '%s'", name, value);
+    return false;
+}
```
