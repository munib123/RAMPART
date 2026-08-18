# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in cpp
**Pair ID:** 2102_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2102_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```cpp
Lines 7-47 of the vulnerable file.

   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/

#if !defined(SKIP_USER_CHANGE)

#include "hphp/util/capability.h"
#include "hphp/util/logger.h"
#include "folly/String.h"
#include <linux/types.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <pwd.h>

namespace HPHP {
///////////////////////////////////////////////////////////////////////////////

static bool setInitialCapabilities() {
  cap_t cap_d = cap_init();
  if (cap_d != nullptr) {
    cap_value_t cap_list[] = {CAP_NET_BIND_SERVICE, CAP_SYS_RESOURCE,
                              CAP_SETUID, CAP_SETGID, CAP_SYS_NICE};
    cap_clear(cap_d);

    if (cap_set_flag(cap_d, CAP_PERMITTED, 5, cap_list, CAP_SET) < 0 ||
        cap_set_flag(cap_d, CAP_EFFECTIVE, 5, cap_list, CAP_SET) < 0) {
      Logger::Error("cap_set_flag failed");
      return false;
    }

    if (cap_set_proc(cap_d) == -1) {
      Logger::Error("cap_set_proc failed");
      return false;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,6 +24,7 @@
 #include <sys/prctl.h>
 #include <sys/types.h>
 #include <pwd.h>
+#include <grp.h>
 
 namespace HPHP {
 ///////////////////////////////////////////////////////////////////////////////
@@ -102,6 +103,12 @@
       return false;
     }
 
+    if (initgroups(pw->pw_name, pw->pw_gid) < 0) {
+      Logger::Error("unable to drop supplementary group privs: %s",
+                    folly::errnoStr(errno).c_str());
+      return false;
+    }
+
     if (pw->pw_gid == 0 || setgid(pw->pw_gid) < 0) {
       Logger::Error("unable to drop gid privs: %s",
                     folly::errnoStr(errno).c_str());
```
