# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 3820_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3820_4`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 14-54 of the vulnerable file.

 */
package org.candlepin.sync;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.candlepin.config.CandlepinCommonTestConfig;
import org.candlepin.config.Config;
import org.candlepin.config.ConfigProperties;
import org.candlepin.model.ExporterMetadata;
import org.candlepin.model.ExporterMetadataCurator;
import org.candlepin.model.Owner;
import org.candlepin.sync.Importer.ImportFile;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,7 @@
 import java.io.FileOutputStream;
 import java.io.FileWriter;
 import java.io.IOException;
+import java.io.InputStream;
 import java.io.PrintStream;
 import java.io.Reader;
 import java.net.URISyntaxException;
@@ -49,6 +50,7 @@
 import org.candlepin.model.ExporterMetadata;
 import org.candlepin.model.ExporterMetadataCurator;
 import org.candlepin.model.Owner;
+import org.candlepin.pki.PKIUtility;
 import org.candlepin.sync.Importer.ImportFile;
 import org.codehaus.jackson.JsonGenerationException;
 import org.codehaus.jackson.map.JsonMappingException;
@@ -353,11 +355,12 @@
         assertTrue(false);
     }
 
-    @Test
-    public void testImportZipSigConsumerNotZip()
-        throws IOException, ImporterException {
-        Importer i = new Importer(null, null, null, null, null, null, null,
-            null, config, null, null, null, i18n);
+    @Test(expected = ImportConflictException.class)
+    public void testImportBadSignature()
+        throws IOException, ImporterException {
+        PKIUtility pki = mock(PKIUtility.class);
+        Importer i = new Importer(null, null, null, null, null, null, null,
+            pki, config, null, null, null, i18n);
 
         Owner owner = mock(Owner.class);
         ConflictOverrides co = mock(ConflictOverrides.class);
@@ -373,25 +376,58 @@
         addFileToArchive(out, ceArchive);
         out.close();
 
+        i.loadExport(owner, archive, co);
+    }
+
+    @Test
+    public void testImportBadConsumerZip() throws Exception {
+        PKIUtility pki = mock(PKIUtility.class);
+        Importer i = new Importer(null, null, null, null, null, null, null,
+            pki, config, null, null, null, i18n);
+
+        Owner owner = mock(Owner.class);
+        ConflictOverrides co = mock(ConflictOverrides.class);
+
+        // Mock a passed signature check:
+        when(pki.verifySHA256WithRSAHashWithUpstreamCACert(any(InputStream.class),
+            any(byte [].class))).thenReturn(true);
+
+        File archive = new File("/tmp/file.zip");
+        ZipOutputStream out = new ZipOutputStream(new FileOutputStream(archive));
+        out.putNextEntry(new ZipEntry("signature"));
+        out.write("This is the placeholder for the signature file".getBytes());
+        File ceArchive = new File("/tmp/consumer_export.zip");
+        FileOutputStream fos = new FileOutputStream(ceArchive);
+        fos.write("This is just a flat file".getBytes());
+        fos.close();
+        addFileToArchive(out, ceArchive);
+        out.close();
+
         try {
             i.loadExport(owner, archive, co);
         }
         catch (ImportExtractionException e) {
-            assertEquals(e.getMessage(), i18n.tr("The archive {0} is " +
-                "not a properly compressed file or is empty", "consumer_export.zip"));
-            return;
-        }
-        assertTrue(false);
+            System.out.println(e.getMessage());
+            assertTrue(e.getMessage().contains(
+                "not a properly compressed file or is empty"));
+            return;
+        }
+        fail();
     }
 
     @Test
     public void testImportZipSigAndEmptyConsumerZip()
-        throws IOException, ImporterException {
-        Importer i = new Importer(null, null, null, null, null, null, null,
-            null, config, null, null, null, i18n);
-
-        Owner owner = mock(Owner.class);
-        ConflictOverrides co = mock(ConflictOverrides.class);
+        throws Exception {
+        PKIUtility pki = mock(PKIUtility.class);
+        Importer i = new Importer(null, null, null, null, null, null, null,
+            pki, config, null, null, null, i18n);
+
+        Owner owner = mock(Owner.class);
+        ConflictOverrides co = mock(ConflictOverrides.class);
+
+        // Mock a passed signature check:
+        when(pki.verifySHA256WithRSAHashWithUpstreamCACert(any(InputStream.class),
+            any(byte [].class))).thenReturn(true);
 
         File archive = new File("/tmp/file.zip");
         ZipOutputStream out = new ZipOutputStream(new FileOutputStream(archive));
@@ -408,11 +444,10 @@
             i.loadExport(owner, archive, co);
         }
         catch (ImportExtractionException e) {
-            assertEquals(e.getMessage(), i18n.tr("The consumer_export " +
-                "archive has no contents"));
-            return;
-        }
-        assertTrue(false);
+            assertTrue(e.getMessage().contains("consumer_export archive has no contents"));
+            return;
+        }
+        fail();
     }
 
     @Test
```
