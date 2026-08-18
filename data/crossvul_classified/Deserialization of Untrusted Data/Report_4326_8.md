# CrossVul Fix Pair: Deserialization of Untrusted Data in csharp
**Pair ID:** 4326_8
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4326_8`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```csharp
Lines 1-20 of the vulnerable file.

namespace DatabaseSchemaReader.SqlGen
{
    /// <summary>
    /// Generate Ddl for all tables in schema.
    /// </summary>
    public interface ITablesGenerator
    {
        /// <summary>
        /// Indicates whether schema will be written in DDL
        /// </summary>
        /// <value><c>true</c> if schema is written; otherwise, <c>false</c>.</value>
        bool IncludeSchema { get; set; }

        /// <summary>
        /// Writes this ddl script.
        /// </summary>
        /// <returns></returns>
        string Write();
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,11 @@
         bool IncludeSchema { get; set; }
 
         /// <summary>
+        /// Escape the table and column names
+        /// </summary>
+        bool EscapeNames { get; set; }
+
+        /// <summary>
         /// Writes this ddl script.
         /// </summary>
         /// <returns></returns>
```
