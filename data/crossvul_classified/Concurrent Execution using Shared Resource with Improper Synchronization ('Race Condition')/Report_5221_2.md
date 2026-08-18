# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5221_2
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5221_2`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 82-122 of the vulnerable file.

static const char *proc_info_dummy(void *a __attribute__((unused)),
                                   const char *b __attribute__((unused)),
                                   const char *c __attribute__((unused)),
                                   const char *d __attribute__((unused)),
                                   const unsigned int e __attribute__((unused)))
{
  return 0;
}

/* this is to be able to call set_thd_proc_info from the C code */
const char *(*proc_info_hook)(void *, const char *, const char *, const char *,
                              const unsigned int)= proc_info_dummy;
void (*debug_sync_C_callback_ptr)(MYSQL_THD, const char *, size_t)= 0;

	/* How to disable options */
my_bool my_disable_locking=0;
my_bool my_disable_sync=0;
my_bool my_disable_async_io=0;
my_bool my_disable_flush_key_blocks=0;
my_bool my_disable_symlinks=0;

/*
  Note that PSI_hook and PSI_server are unconditionally
  (no ifdef HAVE_PSI_INTERFACE) defined.
  This is to ensure binary compatibility between the server and plugins,
  in the case when:
  - the server is not compiled with HAVE_PSI_INTERFACE
  - a plugin is compiled with HAVE_PSI_INTERFACE
  See the doxygen documentation for the performance schema.
*/

/**
  Hook for the instrumentation interface.
  Code implementing the instrumentation interface should register here.
*/
struct PSI_bootstrap *PSI_hook= NULL;

/**
  Instance of the instrumentation interface for the MySQL server.
  @todo This is currently a global variable, which is handy when
  compiling instrumented code that is bundled with the server.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -99,6 +99,7 @@
 my_bool my_disable_async_io=0;
 my_bool my_disable_flush_key_blocks=0;
 my_bool my_disable_symlinks=0;
+my_bool my_disable_copystat_in_redel=0;
 
 /*
   Note that PSI_hook and PSI_server are unconditionally
```
