# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4038_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4038_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 1-37 of the vulnerable file.

/*
 * Copyright (C) 2004-2020 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "znctest.h"
#include <gmock/gmock.h>

using testing::HasSubstr;

namespace znc_inttest {
namespace {

TEST(Config, AlreadyExists) {
    QTemporaryDir dir;
    WriteConfig(dir.path());
    Process p(ZNC_BIN_DIR "/znc", QStringList() << "--debug"
                                                << "--datadir" << dir.path()
                                                << "--makeconf");
    p.ReadUntil("already exists");
    p.CanDie();
}

TEST_F(ZNCTest, Connect) {
    auto znc = Run();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,8 +14,9 @@
  * limitations under the License.
  */
 
+#include <gmock/gmock.h>
+
 #include "znctest.h"
-#include <gmock/gmock.h>
 
 using testing::HasSubstr;
 
@@ -244,7 +245,8 @@
     client.Write("USER user/test x x :x");
     QByteArray cap_ls;
     client.ReadUntilAndGet(" LS :", cap_ls);
-    ASSERT_THAT(cap_ls.toStdString(), AllOf(HasSubstr("cap-notify"), Not(HasSubstr("away-notify"))));
+    ASSERT_THAT(cap_ls.toStdString(),
+                AllOf(HasSubstr("cap-notify"), Not(HasSubstr("away-notify"))));
     client.Write("CAP REQ :cap-notify");
     client.ReadUntil("ACK :cap-notify");
     client.Write("CAP END");
@@ -284,5 +286,15 @@
     ircd.ReadUntil("JOIN #znc secret");
 }
 
+TEST_F(ZNCTest, StatusEchoMessage) {
+    auto znc = Run();
+    auto ircd = ConnectIRCd();
+    auto client = LoginClient();
+    client.Write("CAP REQ :echo-message");
+    client.Write("PRIVMSG *status :blah");
+    client.ReadUntil(":nick!user@irc.znc.in PRIVMSG *status :blah");
+    client.ReadUntil(":*status!znc@znc.in PRIVMSG nick :Unknown command");
+}
+
 }  // namespace
 }  // namespace znc_inttest
```
