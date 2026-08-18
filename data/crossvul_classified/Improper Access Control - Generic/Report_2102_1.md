# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in cpp
**Pair ID:** 2102_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2102_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```cpp
Lines 8-48 of the vulnerable file.

   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/
#include "hphp/util/light-process.h"

#include <string>
#include <vector>

#include <boost/scoped_array.hpp>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <afdt.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>

#include "folly/String.h"

#include "hphp/util/process.h"
#include "hphp/util/logger.h"

namespace HPHP {

///////////////////////////////////////////////////////////////////////////////
// helper functions

Mutex LightProcess::s_mutex;

static bool send_fd(int afdt_fd, int fd) {
  afdt_error_t err;
  errno = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,6 +25,7 @@
 #include <sys/socket.h>
 
 #include <afdt.h>
+#include <grp.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <poll.h>
@@ -299,6 +300,7 @@
     struct passwd *pw = getpwnam(uname.c_str());
     if (pw) {
       if (pw->pw_gid) {
+        initgroups(pw->pw_name, pw->pw_gid);
         setgid(pw->pw_gid);
       }
       if (pw->pw_uid) {
```
