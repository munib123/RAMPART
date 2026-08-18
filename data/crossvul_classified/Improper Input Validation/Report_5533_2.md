# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5533_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5533_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 601-660 of the vulnerable file.

         * we have to save now */
         time_t now = time(NULL);
         for (j = 0; j < server.saveparamslen; j++) {
            struct saveparam *sp = server.saveparams+j;

            if (server.dirty >= sp->changes &&
                now-server.lastsave > sp->seconds) {
                redisLog(REDIS_NOTICE,"%d changes in %d seconds. Saving...",
                    sp->changes, sp->seconds);
                rdbSaveBackground(server.dbfilename);
                break;
            }
         }
    }

    /* Expire a few keys per cycle, only if this is a master.
     * On slaves we wait for DEL operations synthesized by the master
     * in order to guarantee a strict consistency. */
    if (server.masterhost == NULL) activeExpireCycle();

    /* Swap a few keys on disk if we are over the memory limit and VM
     * is enbled. Try to free objects from the free list first. */
    if (vmCanSwapOut()) {
        while (server.vm_enabled && zmalloc_used_memory() >
                server.vm_max_memory)
        {
            int retval = (server.vm_max_threads == 0) ?
                        vmSwapOneObjectBlocking() :
                        vmSwapOneObjectThreaded();
            if (retval == REDIS_ERR && !(loops % 300) &&
                zmalloc_used_memory() >
                (server.vm_max_memory+server.vm_max_memory/10))
            {
                redisLog(REDIS_WARNING,"WARNING: vm-max-memory limit exceeded by more than 10%% but unable to swap more objects out!");
            }
            /* Note that when using threade I/O we free just one object,
             * because anyway when the I/O thread in charge to swap this
             * object out will finish, the handler of completed jobs
             * will try to swap more objects if we are still out of memory. */
            if (retval == REDIS_ERR || server.vm_max_threads > 0) break;
        }
    }

    /* Replication cron function -- used to reconnect to master and
     * to detect transfer failures. */
    if (!(loops % 10)) replicationCron();

    return 100;
}

/* This function gets called every time Redis is entering the
 * main loop of the event driven library, that is, before to sleep
 * for ready file descriptors. */
void beforeSleep(struct aeEventLoop *eventLoop) {
    REDIS_NOTUSED(eventLoop);
    listNode *ln;
    redisClient *c;

    /* Awake clients that got all the swapped keys they requested */
    if (server.vm_enabled && listLength(server.io_ready_clients)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -618,27 +618,12 @@
      * in order to guarantee a strict consistency. */
     if (server.masterhost == NULL) activeExpireCycle();
 
-    /* Swap a few keys on disk if we are over the memory limit and VM
-     * is enbled. Try to free objects from the free list first. */
-    if (vmCanSwapOut()) {
-        while (server.vm_enabled && zmalloc_used_memory() >
-                server.vm_max_memory)
-        {
-            int retval = (server.vm_max_threads == 0) ?
-                        vmSwapOneObjectBlocking() :
-                        vmSwapOneObjectThreaded();
-            if (retval == REDIS_ERR && !(loops % 300) &&
-                zmalloc_used_memory() >
-                (server.vm_max_memory+server.vm_max_memory/10))
-            {
-                redisLog(REDIS_WARNING,"WARNING: vm-max-memory limit exceeded by more than 10%% but unable to swap more objects out!");
-            }
-            /* Note that when using threade I/O we free just one object,
-             * because anyway when the I/O thread in charge to swap this
-             * object out will finish, the handler of completed jobs
-             * will try to swap more objects if we are still out of memory. */
-            if (retval == REDIS_ERR || server.vm_max_threads > 0) break;
-        }
+    /* Remove a few cached objects from memory if we are over the
+     * configured memory limit */
+    while (server.ds_enabled && zmalloc_used_memory() >
+            server.cache_max_memory)
+    {
+        cacheFreeOneEntry();
     }
 
     /* Replication cron function -- used to reconnect to master and
@@ -656,8 +641,8 @@
     listNode *ln;
     redisClient *c;
 
-    /* Awake clients that got all the swapped keys they requested */
-    if (server.vm_enabled && listLength(server.io_ready_clients)) {
+    /* Awake clients that got all the on disk keys they requested */
+    if (server.ds_enabled && listLength(server.io_ready_clients)) {
         listIter li;
 
         listRewind(server.io_ready_clients,&li);
@@ -668,7 +653,7 @@
             /* Resume the client. */
             listDelNode(server.io_ready_clients,ln);
             c->flags &= (~REDIS_IO_WAIT);
-            server.vm_blocked_clients--;
+            server.cache_blocked_clients--;
             aeCreateFileEvent(server.el, c->fd, AE_READABLE,
                 readQueryFromClient, c);
             cmd = lookupCommand(c->argv[0]->ptr);
@@ -787,13 +772,10 @@
     server.maxmemory = 0;
     server.maxmemory_policy = REDIS_MAXMEMORY_VOLATILE_LRU;
     server.maxmemory_samples = 3;
-    server.vm_enabled = 0;
-    server.vm_swap_file = zstrdup("/tmp/redis-%p.vm");
-    server.vm_page_size = 256;          /* 256 bytes per page */
-    server.vm_pages = 1024*1024*100;    /* 104 millions of pages */
-    server.vm_max_memory = 1024LL*1024*1024*1; /* 1 GB of RAM */
-    server.vm_max_threads = 4;
-    server.vm_blocked_clients = 0;
+    server.ds_enabled = 0;
+    server.ds_path = zstrdup("/tmp/redis.ds");
+    server.cache_max_memory = 64LL*1024*1024; /* 64 MB of RAM */
+    server.cache_blocked_clients = 0;
     server.hash_max_zipmap_entries = REDIS_HASH_MAX_ZIPMAP_ENTRIES;
     server.hash_max_zipmap_value = REDIS_HASH_MAX_ZIPMAP_VALUE;
     server.list_max_ziplist_entries = REDIS_LIST_MAX_ZIPLIST_ENTRIES;
@@ -873,7 +855,7 @@
         server.db[j].expires = dictCreate(&keyptrDictType,NULL);
         server.db[j].blocking_keys = dictCreate(&keylistDictType,NULL);
         server.db[j].watched_keys = dictCreate(&keylistDictType,NULL);
-        if (server.vm_enabled)
+        if (server.ds_enabled)
             server.db[j].io_keys = dictCreate(&keylistDictType,NULL);
         server.db[j].id = j;
     }
@@ -911,7 +893,7 @@
         }
     }
 
-    if (server.vm_enabled) vmInit();
+    if (server.ds_enabled) dsInit();
 }
 
 /* Populates the Redis Command Table starting from the hard coded list
@@ -1050,8 +1032,8 @@
         queueMultiCommand(c,cmd);
         addReply(c,shared.queued);
     } else {
-        if (server.vm_enabled && server.vm_max_threads > 0 &&
-            blockClientOnSwappedKeys(c,cmd)) return REDIS_ERR;
+        if (server.ds_enabled && blockClientOnSwappedKeys(c,cmd))
+            return REDIS_ERR;
         call(c,cmd);
     }
     return REDIS_OK;
@@ -1072,7 +1054,6 @@
     if (server.appendonly) {
         /* Append only file: fsync() the AOF and exit */
         aof_fsync(server.appendfd);
-        if (server.vm_enabled) unlink(server.vm_swap_file);
     } else if (server.saveparamslen > 0) {
         /* Snapshotting. Perform a SYNC SAVE and exit */
         if (rdbSave(server.dbfilename) != REDIS_OK) {
@@ -1185,7 +1166,7 @@
         "hash_max_zipmap_value:%zu\r\n"
         "pubsub_channels:%ld\r\n"
         "pubsub_patterns:%u\r\n"
-        "vm_enabled:%d\r\n"
+        "ds_enabled:%d\r\n"
         "role:%s\r\n"
         ,REDIS_VERSION,
         redisGitSHA1(),
@@ -1228,7 +1209,7 @@
         server.hash_max_zipmap_value,
         dictSize(server.pubsub_channels),
         listLength(server.pubsub_patterns),
-        server.vm_enabled != 0,
+        server.ds_enabled != 0,
         server.masterhost == NULL ? "master" : "slave"
     );
     if (server.masterhost) {
@@ -1255,33 +1236,13 @@
             );
         }
     }
-    if (server.vm_enabled) {
+    if (server.ds_enabled) {
         lockThreadedIO();
         info = sdscatprintf(info,
-            "vm_conf_max_memory:%llu\r\n"
-            "vm_conf_page_size:%llu\r\n"
-            "vm_conf_pages:%llu\r\n"
-            "vm_stats_used_pages:%llu\r\n"
-            "vm_stats_swapped_objects:%llu\r\n"
-            "vm_stats_swappin_count:%llu\r\n"
-            "vm_stats_swappout_count:%llu\r\n"
-            "vm_stats_io_newjobs_len:%lu\r\n"
-            "vm_stats_io_processing_len:%lu\r\n"
-            "vm_stats_io_processed_len:%lu\r\n"
-            "vm_stats_io_active_threads:%lu\r\n"
-            "vm_stats_blocked_clients:%lu\r\n"
-            ,(unsigned long long) server.vm_max_memory,
-            (unsigned long long) server.vm_page_size,
-            (unsigned long long) server.vm_pages,
-            (unsigned long long) server.vm_stats_used_pages,
-            (unsigned long long) server.vm_stats_swapped_objects,
-            (unsigned long long) server.vm_stats_swapins,
-            (unsigned long long) server.vm_stats_swapouts,
-            (unsigned long) listLength(server.io_newjobs),
-            (unsigned long) listLength(server.io_processing),
-            (unsigned long) listLength(server.io_processed),
-            (unsigned long) server.io_active_threads,
-            (unsigned long) server.vm_blocked_clients
+            "cache_max_memory:%llu\r\n"
+            "cache_blocked_clients:%lu\r\n"
+            ,(unsigned long long) server.cache_max_memory,
+            (unsigned long) server.cache_blocked_clients
         );
         unlockThreadedIO();
     }
```
