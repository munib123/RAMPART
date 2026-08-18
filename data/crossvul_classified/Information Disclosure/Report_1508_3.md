# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1508_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1508_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 45-85 of the vulnerable file.

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


#define load_abrt_conf abrt_load_abrt_conf
int load_abrt_conf(void);
#define free_abrt_conf_data abrt_free_abrt_conf_data
void free_abrt_conf_data(void);

#define load_abrt_conf_file abrt_load_abrt_conf_file
int load_abrt_conf_file(const char *file, map_string_t *settings);

#define load_abrt_plugin_conf_file abrt_load_abrt_plugin_conf_file
int load_abrt_plugin_conf_file(const char *file, map_string_t *settings);

#define save_abrt_conf_file abrt_save_abrt_conf_file
int save_abrt_conf_file(const char *file, map_string_t *settings);

#define save_abrt_plugin_conf_file abrt_save_abrt_plugin_conf_file
int save_abrt_plugin_conf_file(const char *file, map_string_t *settings);


void migrate_to_xdg_dirs(void);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,6 +62,8 @@
 extern char *        g_settings_autoreporting_event;
 #define g_settings_shortenedreporting abrt_g_settings_shortenedreporting
 extern bool          g_settings_shortenedreporting;
+#define g_settings_privatereports abrt_g_settings_privatereports
+extern bool          g_settings_privatereports;
 
 
 #define load_abrt_conf abrt_load_abrt_conf
```
