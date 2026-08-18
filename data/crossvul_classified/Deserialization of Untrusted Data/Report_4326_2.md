# CrossVul Fix Pair: Deserialization of Untrusted Data in csharp
**Pair ID:** 4326_2
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4326_2`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```csharp
Lines 1-36 of the vulnerable file.

﻿using System;
using System.Data.Common;
using DatabaseSchemaReader.DataSchema;

namespace DatabaseSchemaReader.Data
{
    /// <summary>
    /// Reads a database table schema and data, and writes data to INSERT statements (for copies or backup)
    /// </summary>
    /// <remarks>
    /// This wraps Reader and InsertWriter to provide a higher level API.
    /// </remarks>
    public class ScriptWriter
    {
        private int _pageSize = 1000;

        /// <summary>
        /// Gets or sets the maximum number of records returned. Default is 1000.
        /// </summary>
        /// <value>The size of the page.</value>
        public int PageSize
        {
            get { return _pageSize; }
            set
            {
                if (value <= 0) throw new InvalidOperationException("Must be a positive number");
                if (value > 10000) throw new InvalidOperationException("Value is too large - consider another method");
                _pageSize = value;
            }
        }

        /// <summary>
        /// Include identity values in INSERTs
        /// </summary>
        /// <value>
        ///   <c>true</c> if include identity; otherwise, <c>false</c>.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,6 +13,11 @@
     public class ScriptWriter
     {
         private int _pageSize = 1000;
+
+        /// <summary>
+        /// Escape table and column names (default true)
+        /// </summary>
+        public bool EscapeNames { get; set; } = true;
 
         /// <summary>
         /// Gets or sets the maximum number of records returned. Default is 1000.
@@ -85,6 +90,7 @@
             var w = new InsertWriter(databaseTable, dt);
             w.IncludeIdentity = IncludeIdentity;
             w.IncludeBlobs = IncludeBlobs;
+            w.EscapeNames = EscapeNames;
             var providerName = connection.GetType().Namespace;
             return w.Write(FindSqlType(providerName));
         }
@@ -129,6 +135,7 @@
             var w = new InsertWriter(databaseTable, dt);
             w.IncludeIdentity = IncludeIdentity;
             w.IncludeBlobs = IncludeBlobs;
+            w.EscapeNames = EscapeNames;
             return w.Write(FindSqlType(providerName));
         }
 
```
