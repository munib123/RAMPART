# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1508_6
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1508_6`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 171-211 of the vulnerable file.

{
    unsigned countdown = MAX_DUMPED_DD_COUNT; /* do not report hundreds of oopses */

    log_notice("Saving %u oopses as problem dirs", oops_cnt >= countdown ? countdown : oops_cnt);

    char *cmdline_str = xmalloc_fopen_fgetline_fclose("/proc/cmdline");
    char *fips_enabled = xmalloc_fopen_fgetline_fclose("/proc/sys/crypto/fips_enabled");
    char *proc_modules = xmalloc_open_read_close("/proc/modules", /*maxsize:*/ NULL);
    char *suspend_stats = xmalloc_open_read_close("/sys/kernel/debug/suspend_stats", /*maxsize:*/ NULL);

    time_t t = time(NULL);
    const char *iso_date = iso_date_string(&t);
    /* dump should be readable by all if we're run with -x */
    uid_t my_euid = (uid_t)-1L;
    mode_t mode = DEFAULT_DUMP_DIR_MODE | S_IROTH;
    /* and readable only for the owner otherwise */
    if (!world_readable_dump)
    {
        mode = DEFAULT_DUMP_DIR_MODE;
        my_euid = geteuid();
    }

    pid_t my_pid = getpid();
    unsigned idx = 0;
    unsigned errors = 0;
    while (idx < oops_cnt)
    {
        char base[sizeof("oops-YYYY-MM-DD-hh:mm:ss-%lu-%lu") + 2 * sizeof(long)*3];
        sprintf(base, "oops-%s-%lu-%lu", iso_date, (long)my_pid, (long)idx);
        char *path = concat_path_file(debug_dumps_dir, base);

        struct dump_dir *dd = dd_create(path, /*uid:*/ my_euid, mode);
        if (dd)
        {
            dd_create_basic_files(dd, /*uid:*/ my_euid, NULL);
            save_oops_data_in_dump_dir(dd, (char*)g_list_nth_data(oops_list, idx++), proc_modules);
            dd_save_text(dd, FILENAME_ABRT_VERSION, VERSION);
            dd_save_text(dd, FILENAME_ANALYZER, "Kerneloops");
            dd_save_text(dd, FILENAME_TYPE, "Kerneloops");
            if (cmdline_str)
                dd_save_text(dd, FILENAME_CMDLINE, cmdline_str);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,6 +188,14 @@
     {
         mode = DEFAULT_DUMP_DIR_MODE;
         my_euid = geteuid();
+    }
+    if (g_settings_privatereports)
+    {
+        if (world_readable_dump)
+            log("Not going to make dump directories world readable because PrivateReports is on");
+
+        mode = DEFAULT_DUMP_DIR_MODE;
+        my_euid = 0;
     }
 
     pid_t my_pid = getpid();
```
