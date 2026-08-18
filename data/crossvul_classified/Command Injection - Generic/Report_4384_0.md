# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in cpp
**Pair ID:** 4384_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4384_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```cpp
Lines 1-39 of the vulnerable file.

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "osquery/sql/sqlite_util.h"
#include "osquery/sql/virtual_table.h"

#include <osquery/core/plugins/sql.h>

#include <osquery/utils/conversions/castvariant.h>

#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

#include <osquery/utils/conversions/split.h>

#include <boost/lexical_cast.hpp>

namespace osquery {

FLAG(string,
     disable_tables,
     "",
     "Comma-delimited list of table names to be disabled");

FLAG(string,
     enable_tables,
     "",
     "Comma-delimited list of table names to be enabled");

FLAG(string, nullvalue, "", "Set string for NULL values, default ''");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,7 @@
 
 #include <osquery/core/core.h>
 #include <osquery/core/flags.h>
+#include <osquery/core/shutdown.h>
 #include <osquery/logger/logger.h>
 #include <osquery/registry/registry_factory.h>
 #include <osquery/sql/sql.h>
@@ -270,6 +271,23 @@
   }
 }
 
+// This function is called by SQLite when a statement is prepared and we use
+// it to allowlist specific actions.
+int sqliteAuthorizer(void* userData,
+                     int code,
+                     const char* arg3,
+                     const char* arg4,
+                     const char* arg5,
+                     const char* arg6) {
+  if (kAllowedSQLiteActionCodes.count(code) > 0) {
+    return SQLITE_OK;
+  }
+  LOG(ERROR) << "Authorizer denied action " << code << " "
+             << (arg3 ? arg3 : "null") << " " << (arg4 ? arg4 : "null") << " "
+             << (arg5 ? arg5 : "null") << " " << (arg6 ? arg6 : "null");
+  return SQLITE_DENY;
+}
+
 static inline void openOptimized(sqlite3*& db) {
   sqlite3_open(":memory:", &db);
 
@@ -290,6 +308,12 @@
   registerFilesystemExtensions(db);
   registerHashingExtensions(db);
   registerEncodingExtensions(db);
+
+  auto rc = sqlite3_set_authorizer(db, &sqliteAuthorizer, nullptr);
+  if (rc != SQLITE_OK) {
+    LOG(ERROR) << "Failed to set sqlite authorizer: " << sqlite3_errmsg(db);
+    requestShutdown(rc);
+  }
 }
 
 void SQLiteDBInstance::init() {
@@ -458,6 +482,7 @@
   if (!instance->isPrimary()) {
     attachVirtualTables(instance);
   }
+
   return instance;
 }
 
```
