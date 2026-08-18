# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in cpp
**Pair ID:** 4384_3
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4384_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```cpp
Lines 79-119 of the vulnerable file.

                                  bool respect_locking) {
  sqlite3* db = nullptr;
  if (!pathExists(sqlite_db).ok()) {
    return Status(1, "Database path does not exist");
  }

  auto rc = sqlite3_open_v2(
      sqlite_db.string().c_str(),
      &db,
      (SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX),
      getSystemVFS(respect_locking));
  if (rc != SQLITE_OK || db == nullptr) {
    VLOG(1) << "Cannot open specified database: "
            << getStringForSQLiteReturnCode(rc);
    if (db != nullptr) {
      sqlite3_close(db);
    }
    return Status(1, "Could not open database");
  }

  sqlite3_stmt* stmt = nullptr;
  rc = sqlite3_prepare_v2(db, sqlite_query.c_str(), -1, &stmt, nullptr);
  if (rc != SQLITE_OK) {
    sqlite3_close(db);
    VLOG(1) << "ATC table: Could not prepare database at path: " << sqlite_db;
    return Status(rc, "Could not prepare database");
  }

  while ((sqlite3_step(stmt)) == SQLITE_ROW) {
    auto s = genSqliteTableRow(stmt, results, sqlite_db);
    if (!s.ok()) {
      break;
    }
  }

  // Close handles and free memory
  sqlite3_finalize(stmt);
  sqlite3_close(db);

  return Status{};
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,6 +96,14 @@
     return Status(1, "Could not open database");
   }
 
+  rc = sqlite3_set_authorizer(db, &sqliteAuthorizer, nullptr);
+  if (rc != SQLITE_OK) {
+    sqlite3_close(db);
+    auto errMsg =
+        std::string("Failed to set sqlite authorizer: ") + sqlite3_errmsg(db);
+    return Status(1, errMsg);
+  }
+
   sqlite3_stmt* stmt = nullptr;
   rc = sqlite3_prepare_v2(db, sqlite_query.c_str(), -1, &stmt, nullptr);
   if (rc != SQLITE_OK) {
```
