# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in cpp
**Pair ID:** 2134_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2134_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```cpp
Lines 41-81 of the vulnerable file.

#include "util.h"

#include "wutil.h"
#include "proc.h"
#include "common.h"
#include "env.h"
#include "sanity.h"
#include "expand.h"
#include "history.h"
#include "reader.h"
#include "parser.h"
#include "env_universal.h"
#include "input.h"
#include "event.h"
#include "path.h"

#include "complete.h"
#include "fish_version.h"

/** Command used to start fishd */
#define FISHD_CMD L"fishd ^ /tmp/fishd.log.%s"

// Version for easier debugging
//#define FISHD_CMD L"fishd"

/** Value denoting a null string */
#define ENV_NULL L"\x1d"

/** Some configuration path environment variables */
#define FISH_DATADIR_VAR L"__fish_datadir"
#define FISH_SYSCONFDIR_VAR L"__fish_sysconfdir"
#define FISH_HELPDIR_VAR L"__fish_help_dir"
#define FISH_BIN_DIR L"__fish_bin_dir"

/**
   At init, we read all the environment variables from this array.
*/
extern char **environ;
/**
   This should be the same thing as \c environ, but it is possible only one of the two work...
*/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,7 @@
 #include "fish_version.h"
 
 /** Command used to start fishd */
-#define FISHD_CMD L"fishd ^ /tmp/fishd.log.%s"
+#define FISHD_CMD L"fishd ^ /dev/null"
 
 // Version for easier debugging
 //#define FISHD_CMD L"fishd"
```
