# CrossVul Fix Pair: 7PK in c
**Pair ID:** 4872_1
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4872_1`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 277-317 of the vulnerable file.

    {"evalsha",evalShaCommand,-3,"s",0,evalGetKeys,0,0,0,0,0},
    {"slowlog",slowlogCommand,-2,"a",0,NULL,0,0,0,0,0},
    {"script",scriptCommand,-2,"s",0,NULL,0,0,0,0,0},
    {"time",timeCommand,1,"RF",0,NULL,0,0,0,0,0},
    {"bitop",bitopCommand,-4,"wm",0,NULL,2,-1,1,0,0},
    {"bitcount",bitcountCommand,-2,"r",0,NULL,1,1,1,0,0},
    {"bitpos",bitposCommand,-3,"r",0,NULL,1,1,1,0,0},
    {"wait",waitCommand,3,"s",0,NULL,0,0,0,0,0},
    {"command",commandCommand,0,"lt",0,NULL,0,0,0,0,0},
    {"geoadd",geoaddCommand,-5,"wm",0,NULL,1,1,1,0,0},
    {"georadius",georadiusCommand,-6,"w",0,NULL,1,1,1,0,0},
    {"georadiusbymember",georadiusByMemberCommand,-5,"w",0,NULL,1,1,1,0,0},
    {"geohash",geohashCommand,-2,"r",0,NULL,1,1,1,0,0},
    {"geopos",geoposCommand,-2,"r",0,NULL,1,1,1,0,0},
    {"geodist",geodistCommand,-4,"r",0,NULL,1,1,1,0,0},
    {"pfselftest",pfselftestCommand,1,"a",0,NULL,0,0,0,0,0},
    {"pfadd",pfaddCommand,-2,"wmF",0,NULL,1,1,1,0,0},
    {"pfcount",pfcountCommand,-2,"r",0,NULL,1,-1,1,0,0},
    {"pfmerge",pfmergeCommand,-2,"wm",0,NULL,1,-1,1,0,0},
    {"pfdebug",pfdebugCommand,-3,"w",0,NULL,0,0,0,0,0},
    {"latency",latencyCommand,-2,"aslt",0,NULL,0,0,0,0,0}
};

struct evictionPoolEntry *evictionPoolAlloc(void);

/*============================ Utility functions ============================ */

/* Low level logging. To use only for very big messages, otherwise
 * serverLog() is to prefer. */
void serverLogRaw(int level, const char *msg) {
    const int syslogLevelMap[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING };
    const char *c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & LL_RAW);
    int log_to_stdout = server.logfile[0] == '\0';

    level &= 0xff; /* clear flags */
    if (level < server.verbosity) return;

    fp = log_to_stdout ? stdout : fopen(server.logfile,"a");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -294,6 +294,8 @@
     {"pfcount",pfcountCommand,-2,"r",0,NULL,1,-1,1,0,0},
     {"pfmerge",pfmergeCommand,-2,"wm",0,NULL,1,-1,1,0,0},
     {"pfdebug",pfdebugCommand,-3,"w",0,NULL,0,0,0,0,0},
+    {"post",securityWarningCommand,-1,"lt",0,NULL,0,0,0,0,0},
+    {"host:",securityWarningCommand,-1,"lt",0,NULL,0,0,0,0,0},
     {"latency",latencyCommand,-2,"aslt",0,NULL,0,0,0,0,0}
 };
 
```
