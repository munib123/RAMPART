# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1564_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1564_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 30-70 of the vulnerable file.

int vdprintf(int d, const char *format, va_list ap);
#endif


#define low_free_space abrt_low_free_space
/**
  @brief Checks if there is enough free space to store the problem data

  @param setting_MaxCrashReportsSize Maximum data size
  @param dump_location Location to check for the available space
*/
int low_free_space(unsigned setting_MaxCrashReportsSize, const char *dump_location);

#define trim_problem_dirs abrt_trim_problem_dirs
void trim_problem_dirs(const char *dirname, double cap_size, const char *exclude_path);
#define run_unstrip_n abrt_run_unstrip_n
char *run_unstrip_n(const char *dump_dir_name, unsigned timeout_sec);
#define get_backtrace abrt_get_backtrace
char *get_backtrace(const char *dump_dir_name, unsigned timeout_sec, const char *debuginfo_dirs);


#define g_settings_nMaxCrashReportsSize abrt_g_settings_nMaxCrashReportsSize
extern unsigned int  g_settings_nMaxCrashReportsSize;
#define g_settings_sWatchCrashdumpArchiveDir abrt_g_settings_sWatchCrashdumpArchiveDir
extern char *        g_settings_sWatchCrashdumpArchiveDir;
#define g_settings_dump_location abrt_g_settings_dump_location
extern char *        g_settings_dump_location;
#define g_settings_delete_uploaded abrt_g_settings_delete_uploaded
extern bool          g_settings_delete_uploaded;
#define g_settings_autoreporting abrt_g_settings_autoreporting
extern bool          g_settings_autoreporting;
#define g_settings_autoreporting_event abrt_g_settings_autoreporting_event
extern char *        g_settings_autoreporting_event;
#define g_settings_shortenedreporting abrt_g_settings_shortenedreporting
extern bool          g_settings_shortenedreporting;
#define g_settings_privatereports abrt_g_settings_privatereports
extern bool          g_settings_privatereports;


#define load_abrt_conf abrt_load_abrt_conf
int load_abrt_conf(void);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,6 +47,10 @@
 #define get_backtrace abrt_get_backtrace
 char *get_backtrace(const char *dump_dir_name, unsigned timeout_sec, const char *debuginfo_dirs);
 
+#define dir_is_in_dump_location abrt_dir_is_in_dump_location
+bool dir_is_in_dump_location(const char *dir_name);
+#define dir_has_correct_permissions abrt_dir_has_correct_permissions
+bool dir_has_correct_permissions(const char *dir_name);
 
 #define g_settings_nMaxCrashReportsSize abrt_g_settings_nMaxCrashReportsSize
 extern unsigned int  g_settings_nMaxCrashReportsSize;
```
