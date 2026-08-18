# CrossVul Fix Pair: Deserialization of Untrusted Data in csharp
**Pair ID:** 4326_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4326_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```csharp
Lines 1-37 of the vulnerable file.

﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using DatabaseSchemaReader.DataSchema;

namespace DatabaseSchemaReader.SqlGen
{
    abstract class ConstraintWriterBase
    {
        protected readonly DatabaseTable Table;

        protected ConstraintWriterBase(DatabaseTable table)
        {
            Table = table;
        }

        protected abstract ISqlFormatProvider SqlFormatProvider();

        protected string EscapeName(string name)
        {
            return SqlFormatProvider().Escape(name);
        }

        public bool IncludeSchema { get; set; }

        public Func<DatabaseConstraint, bool> CheckConstraintExcluder { get; set; }
        public Func<string, string> TranslateCheckConstraint { get; set; }

        /// <summary>
        /// Writes the table-specific constraints (primary key, unique, constraint)
        /// </summary>
        /// <returns></returns>
        public string WriteTableConstraints()
        {
            var sb = new StringBuilder();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,13 +14,16 @@
         protected ConstraintWriterBase(DatabaseTable table)
         {
             Table = table;
+            EscapeNames = true;
         }
 
         protected abstract ISqlFormatProvider SqlFormatProvider();
 
+        public bool EscapeNames { get; set; }
+
         protected string EscapeName(string name)
         {
-            return SqlFormatProvider().Escape(name);
+            return EscapeNames? SqlFormatProvider().Escape(name) : name;
         }
 
         public bool IncludeSchema { get; set; }
@@ -74,6 +77,7 @@
         {
             get { return "ALTER TABLE {0} ADD CONSTRAINT {1} UNIQUE ({2})"; }
         }
+
         private string WriteUniqueKey(DatabaseConstraint uniqueKey)
         {
             var columnList = GetColumnList(uniqueKey.Columns);
```
