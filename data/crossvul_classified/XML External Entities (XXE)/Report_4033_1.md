# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4033_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4033_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1-33 of the vulnerable file.

/*
 * Copyright (c) 2003, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.core;

import org.postgresql.PGConnection;
import org.postgresql.PGProperty;
import org.postgresql.jdbc.FieldMetadata;
import org.postgresql.jdbc.TimestampUtils;
import org.postgresql.util.LruCache;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.TimerTask;

/**
 * Driver-internal connection interface. Application code should not use this interface.
 */
public interface BaseConnection extends PGConnection, Connection {
  /**
   * Cancel the current query executing on this connection.
   *
   * @throws SQLException if something goes wrong.
   */
  void cancelQuery() throws SQLException;

  /**
   * Execute a SQL query that returns a single resultset. Never causes a new transaction to be
   * started regardless of the autocommit setting.
   *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,7 @@
 import org.postgresql.jdbc.FieldMetadata;
 import org.postgresql.jdbc.TimestampUtils;
 import org.postgresql.util.LruCache;
+import org.postgresql.xml.PGXmlFactoryFactory;
 
 import java.sql.Connection;
 import java.sql.ResultSet;
@@ -212,4 +213,12 @@
    * @see PGProperty#READ_ONLY_MODE
    */
   boolean hintReadOnly();
+
+  /**
+   * Retrieve the factory to instantiate XML processing factories.
+   *
+   * @return The factory to use to instantiate XML processing factories
+   * @throws SQLException if the class cannot be found or instantiated.
+   */
+  PGXmlFactoryFactory getXmlFactoryFactory() throws SQLException;
 }
```
