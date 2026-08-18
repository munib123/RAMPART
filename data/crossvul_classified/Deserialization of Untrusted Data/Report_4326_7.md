# CrossVul Fix Pair: Deserialization of Untrusted Data in csharp
**Pair ID:** 4326_7
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4326_7`)

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
    /// Generate a table DDL
    /// </summary>
    public interface ITableGenerator
    {
        /// <summary>
        /// Indicates whether schema will be written in DDL
        /// </summary>
        /// <value><c>true</c> if schema is written; otherwise, <c>false</c>.</value>
        bool IncludeSchema { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to include default values while writing column definitions
        /// </summary>
        /// <value>
        /// <c>true</c> if include default values; otherwise, <c>false</c>.
        /// </value>
        bool IncludeDefaultValues { get; set; }


        /// <summary>
        /// Writes the DDL.
        /// </summary>
        /// <returns></returns>
        string Write();

        /// <summary>
        /// Writes the column.
        /// </summary>
        /// <param name="column">The column.</param>
        /// <returns></returns>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,10 @@
         /// </summary>
         /// <value><c>true</c> if schema is written; otherwise, <c>false</c>.</value>
         bool IncludeSchema { get; set; }
-
+        /// <summary>
+        /// Escape the names (default true)
+        /// </summary>
+        bool EscapeNames { get; set; }
         /// <summary>
         /// Gets or sets a value indicating whether to include default values while writing column definitions
         /// </summary>
@@ -20,7 +23,6 @@
         /// <c>true</c> if include default values; otherwise, <c>false</c>.
         /// </value>
         bool IncludeDefaultValues { get; set; }
-
 
         /// <summary>
         /// Writes the DDL.
```
