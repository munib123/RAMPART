# CrossVul Fix Pair: Deserialization of Untrusted Data in csharp
**Pair ID:** 4326_5
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4326_5`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```csharp
Lines 1-29 of the vulnerable file.

﻿using System;
using System.Text;
using DatabaseSchemaReader.DataSchema;

namespace DatabaseSchemaReader.SqlGen
{
    class DropTables
    {
        public static string Write(DatabaseSchema schema, ISqlFormatProvider formatter)
        {
            var sb = new StringBuilder();
            var lineEnding = formatter.LineEnding();
            //if this is a GO, comment it out too
            if (lineEnding.IndexOf(Environment.NewLine, StringComparison.Ordinal) != -1)
            {
                lineEnding = lineEnding.Replace(Environment.NewLine, Environment.NewLine + "--");
            }
            foreach (var table in schema.Tables)
            {
                foreach (var foreignKey in table.ForeignKeys)
                {
                    sb.AppendLine("-- ALTER TABLE " + formatter.Escape(table.Name) + " DROP CONSTRAINT " + foreignKey.Name + lineEnding);

                }
            }
            foreach (var table in schema.Tables)
            {
                sb.AppendLine("-- DROP TABLE " + formatter.Escape(table.Name) + lineEnding);
            }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 {
     class DropTables
     {
-        public static string Write(DatabaseSchema schema, ISqlFormatProvider formatter)
+        public static string Write(DatabaseSchema schema, ISqlFormatProvider formatter, bool escapeNames)
         {
             var sb = new StringBuilder();
             var lineEnding = formatter.LineEnding();
@@ -19,13 +19,13 @@
             {
                 foreach (var foreignKey in table.ForeignKeys)
                 {
-                    sb.AppendLine("-- ALTER TABLE " + formatter.Escape(table.Name) + " DROP CONSTRAINT " + foreignKey.Name + lineEnding);
-
+                    sb.AppendLine("-- ALTER TABLE " + (escapeNames ? formatter.Escape(table.Name) : table.Name) + 
+                                  " DROP CONSTRAINT " + foreignKey.Name + lineEnding);
                 }
             }
             foreach (var table in schema.Tables)
             {
-                sb.AppendLine("-- DROP TABLE " + formatter.Escape(table.Name) + lineEnding);
+                sb.AppendLine("-- DROP TABLE " + (escapeNames ? formatter.Escape(table.Name) : table.Name) + lineEnding);
             }
             return sb.ToString();
         }
```
