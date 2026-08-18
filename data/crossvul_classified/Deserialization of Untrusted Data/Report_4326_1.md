# CrossVul Fix Pair: Deserialization of Untrusted Data in csharp
**Pair ID:** 4326_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4326_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```csharp
Lines 118-158 of the vulnerable file.


            }
        }

        /// <summary>
        /// Include identity values in INSERTs
        /// </summary>
        /// <value>
        ///   <c>true</c> if include identity; otherwise, <c>false</c>.
        /// </value>
        public bool IncludeIdentity { get; set; }


        /// <summary>
        /// Include BLOB in INSERTS. This is only practical for small blobs for certain databases (eg it works in SqlServer Northwind).
        /// </summary>
        /// <value><c>true</c> if include blobs; otherwise, <c>false</c>.</value>
        public bool IncludeBlobs { get; set; }

        /// <summary>
        /// Writes the INSERTs in the specified SQL dialect
        /// </summary>
        /// <param name="sqlType">Type of the SQL.</param>
        /// <returns></returns>
        public string Write(SqlType sqlType)
        {
            if (_dataTable == null) return null; //wrong constructor used

            _sqlType = sqlType;
            _sqlWriter = new SqlWriter(_databaseTable, sqlType);
            _converter = new Converter(sqlType, _dateTypes);

            PrepareTemplate();

            var sb = new StringBuilder();

            PrepareIdentityInsert(sb);

            foreach (DataRow row in _dataTable.Rows)
            {
                sb.AppendLine(WriteInsert(row));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,6 +135,11 @@
         public bool IncludeBlobs { get; set; }
 
         /// <summary>
+        /// Escape table and column names (default true)
+        /// </summary>
+        public bool EscapeNames { get; set; } = true;
+
+        /// <summary>
         /// Writes the INSERTs in the specified SQL dialect
         /// </summary>
         /// <param name="sqlType">Type of the SQL.</param>
@@ -267,7 +272,7 @@
         {
             var cols = GetAllColumns();
 
-            _template = "INSERT INTO " + _sqlWriter.EscapedTableName + @" (
+            _template = "INSERT INTO " + (EscapeNames ? _sqlWriter.EscapedTableName : _databaseTable.Name) + @" (
 " + FormattedColumns(cols) + @") VALUES (
 {0}
 );
@@ -288,7 +293,9 @@
             {
                 if (IsNotWriteableType(databaseColumn)) continue;
                 if (!IncludeIdentity && databaseColumn.IsAutoNumber) continue;
-                cols.Add(_sqlWriter.EscapedColumnName(databaseColumn.Name));
+                var name = databaseColumn.Name;
+                if (EscapeNames) name = _sqlWriter.EscapedColumnName(databaseColumn.Name);
+                cols.Add(name);
             }
 
             return cols.ToArray();
```
