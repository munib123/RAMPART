# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 4384_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4384_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 11-51 of the vulnerable file.


#include <atomic>
#include <map>
#include <mutex>
#include <unordered_set>

#include <sqlite3.h>

#include <boost/filesystem.hpp>
#include <boost/noncopyable.hpp>

#include <osquery/sql/sql.h>

#include <osquery/utils/mutex.h>

#include <gtest/gtest_prod.h>

#define SQLITE_SOFT_HEAP_LIMIT (5 * 1024 * 1024)

namespace osquery {

class SQLiteDBManager;

/**
 * @brief An RAII wrapper around an `sqlite3` object.
 *
 * The SQLiteDBInstance is also "smart" in that it may unlock access to a
 * managed `sqlite3` resource. If there's no contention then only a single
 * database is needed during the life of an osquery tool.
 *
 * If there is resource contention (multiple threads want access to the SQLite
 * abstraction layer), then the SQLiteDBManager will provide a transient
 * SQLiteDBInstance.
 */
class SQLiteDBInstance : private boost::noncopyable {
 public:
  SQLiteDBInstance() {
    init();
  }
  SQLiteDBInstance(sqlite3*& db, Mutex& mtx);
  ~SQLiteDBInstance();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,6 +28,47 @@
 #define SQLITE_SOFT_HEAP_LIMIT (5 * 1024 * 1024)
 
 namespace osquery {
+
+int sqliteAuthorizer(void* userData,
+                     int code,
+                     const char* arg3,
+                     const char* arg4,
+                     const char* arg5,
+                     const char* arg6);
+
+// Allowlist of SQLite actions. Any action not in this set is denied. See
+// possible values in https://sqlite.org/c3ref/c_alter_table.html.
+// ** Never allow SQLITE_ATTACH ** as it can be used to write arbitrary files.
+const std::unordered_set<int> kAllowedSQLiteActionCodes = {
+    // Enable basic functionality
+    SQLITE_READ,
+    SQLITE_SELECT,
+
+    // Some extensions implement writeable tables
+    SQLITE_INSERT,
+    SQLITE_UPDATE,
+    SQLITE_DELETE,
+
+    // Allow virtual tables to be attached
+    SQLITE_CREATE_VTABLE,
+    SQLITE_DROP_VTABLE,
+
+    // Users may sometimes want to create tables and views
+    SQLITE_CREATE_VIEW,
+    SQLITE_DROP_VIEW,
+    SQLITE_CREATE_TABLE,
+    SQLITE_DROP_TABLE,
+    SQLITE_CREATE_TEMP_TABLE,
+    SQLITE_DROP_TEMP_TABLE,
+    SQLITE_CREATE_TEMP_VIEW,
+    SQLITE_DROP_TEMP_VIEW,
+
+    // Required to allow calling functions in SQL
+    SQLITE_FUNCTION,
+
+    // Required for recursive queries
+    SQLITE_RECURSIVE,
+};
 
 class SQLiteDBManager;
 
```
