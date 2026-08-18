# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4033_3
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4033_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 20-60 of the vulnerable file.

import org.postgresql.core.QueryExecutor;
import org.postgresql.core.ReplicationProtocol;
import org.postgresql.core.ResultHandlerBase;
import org.postgresql.core.ServerVersion;
import org.postgresql.core.SqlCommand;
import org.postgresql.core.TransactionState;
import org.postgresql.core.TypeInfo;
import org.postgresql.core.Utils;
import org.postgresql.core.Version;
import org.postgresql.fastpath.Fastpath;
import org.postgresql.largeobject.LargeObjectManager;
import org.postgresql.replication.PGReplicationConnection;
import org.postgresql.replication.PGReplicationConnectionImpl;
import org.postgresql.util.GT;
import org.postgresql.util.HostSpec;
import org.postgresql.util.LruCache;
import org.postgresql.util.PGBinaryObject;
import org.postgresql.util.PGobject;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import java.io.IOException;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.ClientInfoStatus;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLPermission;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Struct;
import java.sql.Types;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,9 @@
 import org.postgresql.util.PGobject;
 import org.postgresql.util.PSQLException;
 import org.postgresql.util.PSQLState;
+import org.postgresql.xml.DefaultPGXmlFactoryFactory;
+import org.postgresql.xml.LegacyInsecurePGXmlFactoryFactory;
+import org.postgresql.xml.PGXmlFactoryFactory;
 
 import java.io.IOException;
 import java.sql.Array;
@@ -156,6 +159,9 @@
 
   private final LruCache<FieldMetadata.Key, FieldMetadata> fieldMetadataCache;
 
+  private final String xmlFactoryFactoryClass;
+  private PGXmlFactoryFactory xmlFactoryFactory;
+
   final CachedQuery borrowQuery(String sql) throws SQLException {
     return queryExecutor.borrowQuery(sql);
   }
@@ -311,6 +317,8 @@
         false);
 
     replicationConnection = PGProperty.REPLICATION.get(info) != null;
+
+    xmlFactoryFactoryClass = PGProperty.XML_FACTORY_FACTORY.get(info);
   }
 
   private static ReadOnlyBehavior getReadOnlyBehavior(String property) {
@@ -1823,4 +1831,36 @@
     return queryExecutor.getParameterStatus(parameterName);
   }
 
+  @Override
+  public PGXmlFactoryFactory getXmlFactoryFactory() throws SQLException {
+    if (xmlFactoryFactory == null) {
+      if (xmlFactoryFactoryClass == null || xmlFactoryFactoryClass.equals("")) {
+        xmlFactoryFactory = DefaultPGXmlFactoryFactory.INSTANCE;
+      } else if (xmlFactoryFactoryClass.equals("LEGACY_INSECURE")) {
+        xmlFactoryFactory = LegacyInsecurePGXmlFactoryFactory.INSTANCE;
+      } else {
+        Class<?> clazz;
+        try {
+          clazz = Class.forName(xmlFactoryFactoryClass);
+        } catch (ClassNotFoundException ex) {
+          throw new PSQLException(
+              GT.tr("Could not instantiate xmlFactoryFactory: {0}", xmlFactoryFactoryClass),
+              PSQLState.INVALID_PARAMETER_VALUE, ex);
+        }
+        if (!clazz.isAssignableFrom(PGXmlFactoryFactory.class)) {
+          throw new PSQLException(
+              GT.tr("Connection property xmlFactoryFactory must implement PGXmlFactoryFactory: {0}", xmlFactoryFactoryClass),
+              PSQLState.INVALID_PARAMETER_VALUE);
+        }
+        try {
+          xmlFactoryFactory = (PGXmlFactoryFactory) clazz.newInstance();
+        } catch (Exception ex) {
+          throw new PSQLException(
+              GT.tr("Could not instantiate xmlFactoryFactory: {0}", xmlFactoryFactoryClass),
+              PSQLState.INVALID_PARAMETER_VALUE, ex);
+        }
+      }
+    }
+    return xmlFactoryFactory;
+  }
 }
```
