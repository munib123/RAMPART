# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 438_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `438_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 79-100 of the vulnerable file.

extern unsigned os_release;

extern void free_parent_mallocs_startup(bool);
extern void free_parent_mallocs_exit(void);
extern char *make_syslog_ident(const char*);
#ifdef _WITH_VRRP_
extern bool running_vrrp(void);
#endif
#ifdef _WITH_LVS_
extern bool running_checker(void);
#endif
#ifdef _WITH_BFD
extern bool running_bfd(void);
#endif

extern void stop_keepalived(void);
extern void initialise_debug_options(void);
extern int keepalived_main(int, char**); /* The "real" main function */

extern unsigned child_wait_time;

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,5 +96,6 @@
 extern int keepalived_main(int, char**); /* The "real" main function */
 
 extern unsigned child_wait_time;
+extern bool umask_cmdline;
 
 #endif
```
