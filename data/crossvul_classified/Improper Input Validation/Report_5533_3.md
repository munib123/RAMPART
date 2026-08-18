# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5533_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5533_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 423-463 of the vulnerable file.

    int isslave;
    /* Slave specific fields */
    char *masterauth;
    char *masterhost;
    int masterport;
    redisClient *master;    /* client that is master for this slave */
    int replstate;          /* replication status if the instance is a slave */
    off_t repl_transfer_left;  /* bytes left reading .rdb  */
    int repl_transfer_s;    /* slave -> master SYNC socket */
    int repl_transfer_fd;   /* slave -> master SYNC temp file descriptor */
    char *repl_transfer_tmpfile; /* slave-> master SYNC temp file name */
    time_t repl_transfer_lastio; /* unix time of the latest read, for timeout */
    int repl_serve_stale_data; /* Serve stale data when link is down? */
    /* Limits */
    unsigned int maxclients;
    unsigned long long maxmemory;
    int maxmemory_policy;
    int maxmemory_samples;
    /* Blocked clients */
    unsigned int bpop_blocked_clients;
    unsigned int vm_blocked_clients;
    list *unblocked_clients;
    /* Sort parameters - qsort_r() is only available under BSD so we
     * have to take this state global, in order to pass it to sortCompare() */
    int sort_desc;
    int sort_alpha;
    int sort_bypattern;
    /* Virtual memory configuration */
    int vm_enabled;
    char *vm_swap_file;
    off_t vm_page_size;
    off_t vm_pages;
    unsigned long long vm_max_memory;
    /* Zip structure config */
    size_t hash_max_zipmap_entries;
    size_t hash_max_zipmap_value;
    size_t list_max_ziplist_entries;
    size_t list_max_ziplist_value;
    size_t set_max_intset_entries;
    /* Virtual memory state */
    FILE *vm_fp;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -440,7 +440,7 @@
     int maxmemory_samples;
     /* Blocked clients */
     unsigned int bpop_blocked_clients;
-    unsigned int vm_blocked_clients;
+    unsigned int cache_blocked_clients;
     list *unblocked_clients;
     /* Sort parameters - qsort_r() is only available under BSD so we
      * have to take this state global, in order to pass it to sortCompare() */
@@ -448,11 +448,9 @@
     int sort_alpha;
     int sort_bypattern;
     /* Virtual memory configuration */
-    int vm_enabled;
-    char *vm_swap_file;
-    off_t vm_page_size;
-    off_t vm_pages;
-    unsigned long long vm_max_memory;
+    int ds_enabled; /* backend disk in redis.conf */
+    char *ds_path;  /* location of the disk store on disk */
+    unsigned long long cache_max_memory;
     /* Zip structure config */
     size_t hash_max_zipmap_entries;
     size_t hash_max_zipmap_value;
```
