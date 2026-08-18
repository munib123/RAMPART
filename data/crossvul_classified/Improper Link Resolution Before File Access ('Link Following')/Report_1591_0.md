# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1591_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1591_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 661-701 of the vulnerable file.

        }
        log("Saved core dump of pid %lu (%s) to %s (%llu bytes)", (long)pid, executable, path, (long long)core_size);
        return 0;
    }

    unsigned path_len = snprintf(path, sizeof(path), "%s/ccpp-%s-%lu.new",
            g_settings_dump_location, iso_date_string(NULL), (long)pid);
    if (path_len >= (sizeof(path) - sizeof("/"FILENAME_COREDUMP)))
    {
        goto create_user_core;
    }

    /* use fsuid instead of uid, so we don't expose any sensitive
     * information of suided app in /var/tmp/abrt
     */
    dd = dd_create(path, fsuid, DEFAULT_DUMP_DIR_MODE);
    if (dd)
    {
        char *rootdir = get_rootdir(pid);

        dd_create_basic_files(dd, fsuid, (rootdir && strcmp(rootdir, "/") != 0) ? rootdir : NULL);

        char source_filename[sizeof("/proc/%lu/somewhat_long_name") + sizeof(long)*3];
        int source_base_ofs = sprintf(source_filename, "/proc/%lu/smaps", (long)pid);
        source_base_ofs -= strlen("smaps");
        char *dest_filename = concat_path_file(dd->dd_dirname, "also_somewhat_longish_name");
        char *dest_base = strrchr(dest_filename, '/') + 1;

        // Disabled for now: /proc/PID/smaps tends to be BIG,
        // and not much more informative than /proc/PID/maps:
        //copy_file_ext(source_filename, dest_filename, 0640, dd->dd_uid, dd->dd_gid, O_RDONLY, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL);

        strcpy(source_filename + source_base_ofs, "maps");
        strcpy(dest_base, FILENAME_MAPS);
        copy_file_ext(source_filename, dest_filename, 0640, dd->dd_uid, dd->dd_gid, O_RDONLY, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL);

        strcpy(source_filename + source_base_ofs, "limits");
        strcpy(dest_base, FILENAME_LIMITS);
        copy_file_ext(source_filename, dest_filename, 0640, dd->dd_uid, dd->dd_gid, O_RDONLY, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL);

        strcpy(source_filename + source_base_ofs, "cgroup");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -678,7 +678,7 @@
     {
         char *rootdir = get_rootdir(pid);
 
-        dd_create_basic_files(dd, fsuid, (rootdir && strcmp(rootdir, "/") != 0) ? rootdir : NULL);
+        dd_create_basic_files(dd, fsuid, NULL);
 
         char source_filename[sizeof("/proc/%lu/somewhat_long_name") + sizeof(long)*3];
         int source_base_ofs = sprintf(source_filename, "/proc/%lu/smaps", (long)pid);
```
