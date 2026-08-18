# CrossVul Fix Pair: Deserialization of Untrusted Data in csharp
**Pair ID:** 4326_9
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4326_9`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```csharp
Lines 1-27 of the vulnerable file.

﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using DatabaseSchemaReader.DataSchema;
using DatabaseSchemaReader.SqlGen.SqLite;
using DatabaseSchemaReader.Utilities;

namespace DatabaseSchemaReader.SqlGen
{
    class MigrationGenerator : IMigrationGenerator
    {
        private readonly ISqlFormatProvider _sqlFormatProvider;
        private readonly DdlGeneratorFactory _ddlFactory;

        public MigrationGenerator(SqlType sqlType)
        {
            _sqlFormatProvider = SqlFormatFactory.Provider(sqlType);
            _ddlFactory = new DdlGeneratorFactory(sqlType);
            IncludeSchema = (sqlType != SqlType.SqlServerCe && sqlType != SqlType.SQLite);
        }

        /// <summary>
        /// Include the schema when writing table. Must not be set for SQLite as there is no schema.
        /// </summary>
        public bool IncludeSchema { get; set; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,6 @@
 using System.Linq;
 using System.Text;
 using DatabaseSchemaReader.DataSchema;
-using DatabaseSchemaReader.SqlGen.SqLite;
 using DatabaseSchemaReader.Utilities;
 
 namespace DatabaseSchemaReader.SqlGen
@@ -19,6 +18,7 @@
             _sqlFormatProvider = SqlFormatFactory.Provider(sqlType);
             _ddlFactory = new DdlGeneratorFactory(sqlType);
             IncludeSchema = (sqlType != SqlType.SqlServerCe && sqlType != SqlType.SQLite);
+            EscapeNames = true;
         }
 
         /// <summary>
@@ -26,9 +26,16 @@
         /// </summary>
         public bool IncludeSchema { get; set; }
 
+        /// <summary>
+        /// Escape any names
+        /// </summary>
+        public bool EscapeNames { get; set; }
+
         protected virtual ITableGenerator CreateTableGenerator(DatabaseTable databaseTable)
         {
-            return _ddlFactory.TableGenerator(databaseTable);
+            var tableGenerator = _ddlFactory.TableGenerator(databaseTable);
+            if (!EscapeNames) tableGenerator.EscapeNames = false;
+            return tableGenerator;
         }
         protected virtual ISqlFormatProvider SqlFormatProvider()
         {
@@ -37,7 +44,7 @@
 
         public string Escape(string name)
         {
-            return SqlFormatProvider().Escape(name);
+            return EscapeNames ? SqlFormatProvider().Escape(name) : name;
         }
         protected virtual string LineEnding()
         {
@@ -214,6 +221,7 @@
             var constraintWriter = _ddlFactory.ConstraintWriter(databaseTable);
             if (constraintWriter == null) return null;
             constraintWriter.IncludeSchema = IncludeSchema; //cascade setting
+            constraintWriter.EscapeNames = EscapeNames;
             return constraintWriter.WriteConstraint(constraint);
         }
 
```
