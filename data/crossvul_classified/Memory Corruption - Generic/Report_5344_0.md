# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5344_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5344_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 599-640 of the vulnerable file.

                   argc == 2)
        {
            server.slowlog_log_slower_than = strtoll(argv[1],NULL,10);
        } else if (!strcasecmp(argv[0],"latency-monitor-threshold") &&
                   argc == 2)
        {
            server.latency_monitor_threshold = strtoll(argv[1],NULL,10);
            if (server.latency_monitor_threshold < 0) {
                err = "The latency threshold can't be negative";
                goto loaderr;
            }
        } else if (!strcasecmp(argv[0],"slowlog-max-len") && argc == 2) {
            server.slowlog_max_len = strtoll(argv[1],NULL,10);
        } else if (!strcasecmp(argv[0],"client-output-buffer-limit") &&
                   argc == 5)
        {
            int class = getClientTypeByName(argv[1]);
            unsigned long long hard, soft;
            int soft_seconds;

            if (class == -1) {
                err = "Unrecognized client limit class";
                goto loaderr;
            }
            hard = memtoll(argv[2],NULL);
            soft = memtoll(argv[3],NULL);
            soft_seconds = atoi(argv[4]);
            if (soft_seconds < 0) {
                err = "Negative number of seconds in soft limit is invalid";
                goto loaderr;
            }
            server.client_obuf_limits[class].hard_limit_bytes = hard;
            server.client_obuf_limits[class].soft_limit_bytes = soft;
            server.client_obuf_limits[class].soft_limit_seconds = soft_seconds;
        } else if (!strcasecmp(argv[0],"stop-writes-on-bgsave-error") &&
                   argc == 2) {
            if ((server.stop_writes_on_bgsave_err = yesnotoi(argv[1])) == -1) {
                err = "argument must be 'yes' or 'no'"; goto loaderr;
            }
        } else if (!strcasecmp(argv[0],"slave-priority") && argc == 2) {
            server.slave_priority = atoi(argv[1]);
        } else if (!strcasecmp(argv[0],"slave-announce-ip") && argc == 2) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -616,8 +616,9 @@
             unsigned long long hard, soft;
             int soft_seconds;
 
-            if (class == -1) {
-                err = "Unrecognized client limit class";
+            if (class == -1 || class == CLIENT_TYPE_MASTER) {
+                err = "Unrecognized client limit class: the user specified "
+                "an invalid one, or 'master' which has no buffer limits.";
                 goto loaderr;
             }
             hard = memtoll(argv[2],NULL);
@@ -906,7 +907,8 @@
             long val;
 
             if ((j % 4) == 0) {
-                if (getClientTypeByName(v[j]) == -1) {
+                int class = getClientTypeByName(v[j]);
+                if (class == -1 || class == CLIENT_TYPE_MASTER) {
                     sdsfreesplitres(v,vlen);
                     goto badfmt;
                 }
```
