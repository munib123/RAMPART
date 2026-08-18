# CrossVul Fix Pair: Deserialization of Untrusted Data in csharp
**Pair ID:** 4326_6
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4326_6`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```csharp
Lines 1-35 of the vulnerable file.

﻿using DatabaseSchemaReader.DataSchema;

namespace DatabaseSchemaReader.SqlGen
{
    /// <summary>
    /// Performs simple database schema migrations
    /// </summary>
    public interface IMigrationGenerator
    {
        /// <summary>
        /// Include the schema when writing migration sql. Default true (except if detects SQLite, SqlServerCE)
        /// </summary>
        bool IncludeSchema { get; set; }
        /// <summary>
        /// Adds the table. If any primary key, unqiue or check constraints are attached, they are written too (don't write them individually). Foreign keys must be added separately (use <see cref="AddConstraint"/>)
        /// </summary>
        /// <param name="databaseTable">The database table.</param>
        /// <returns></returns>
        string AddTable(DatabaseTable databaseTable);
        /// <summary>
        /// Adds the column.
        /// </summary>
        /// <param name="databaseTable">The database table.</param>
        /// <param name="databaseColumn">The database column.</param>
        /// <returns></returns>
        string AddColumn(DatabaseTable databaseTable, DatabaseColumn databaseColumn);
        /// <summary>
        /// Alters the column.
        /// </summary>
        /// <param name="databaseTable">The database table.</param>
        /// <param name="databaseColumn">The database column.</param>
        /// <param name="originalColumn">The original column.</param>
        /// <returns></returns>
        string AlterColumn(DatabaseTable databaseTable, DatabaseColumn databaseColumn, DatabaseColumn originalColumn);
        /// <summary>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,11 @@
         /// </summary>
         bool IncludeSchema { get; set; }
         /// <summary>
-        /// Adds the table. If any primary key, unqiue or check constraints are attached, they are written too (don't write them individually). Foreign keys must be added separately (use <see cref="AddConstraint"/>)
+        /// Escape the names (default true)
+        /// </summary>
+        bool EscapeNames { get; set; }
+        /// <summary>
+        /// Adds the table. If any primary key, unique or check constraints are attached, they are written too (don't write them individually). Foreign keys must be added separately (use <see cref="AddConstraint"/>)
         /// </summary>
         /// <param name="databaseTable">The database table.</param>
         /// <returns></returns>
```
