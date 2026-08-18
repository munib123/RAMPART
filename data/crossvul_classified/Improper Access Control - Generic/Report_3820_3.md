# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 3820_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3820_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 5-45 of the vulnerable file.

 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package org.candlepin.sync;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.persistence.PersistenceException;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.candlepin.audit.EventSink;
import org.candlepin.config.Config;
import org.candlepin.controller.PoolManager;
import org.candlepin.controller.Refresher;
import org.candlepin.model.CertificateSerialCurator;
import org.candlepin.model.ConsumerType;
import org.candlepin.model.ConsumerTypeCurator;
import org.candlepin.model.ContentCurator;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.Reader;
+import java.security.cert.CertificateException;
 import java.util.HashMap;
 import java.util.HashSet;
 import java.util.LinkedList;
@@ -211,38 +212,35 @@
             tmpDir = new SyncUtils(config).makeTempDir("import");
             extractArchive(tmpDir, exportFile);
 
-//           only need this call when sig file is verified
-//            exportStream = new FileInputStream(new File(tmpDir, "consumer_export.zip"));
-
-            /*
-             * Disabling this once again for a little bit longer. Dependent projects
-             * are not yet ready for it, and we're having some difficulty with the actual
-             * upstream cert to use.
-             *
-             * When we bring this back, we should probably report this conflict
-             * immediately, rather than continuing to extract and trying to find any
-             * other conflicts to pass back.
-             */
-//            boolean verifiedSignature = pki.verifySHA256WithRSAHashWithUpstreamCACert(
-//                exportStream,
-//                loadSignature(new File(tmpDir, "signature")));
-//            if (!verifiedSignature) {
-//                log.warn("Manifest signature check failed.");
-//                if (!forcedConflicts
-//                    .isForced(ImportConflicts.Conflict.SIGNATURE_CONFLICT)) {
-//                    conflicts.addConflict(
-//                        i18n.tr("Failed import file hash check."),
-//                        ImportConflicts.Conflict.SIGNATURE_CONFLICT);
-//                }
-//                else {
-//                    log.warn("Ignoring signature check failure.");
-//                }
-//            }
-
             File signature = new File(tmpDir, "signature");
             if (signature.length() == 0) {
                 throw new ImportExtractionException(i18n.tr("The archive does not " +
                                           "contain the required signature file"));
+            }
+
+            exportStream = new FileInputStream(new File(tmpDir, "consumer_export.zip"));
+            boolean verifiedSignature = pki.verifySHA256WithRSAHashWithUpstreamCACert(
+                exportStream,
+                loadSignature(new File(tmpDir, "signature")));
+            if (!verifiedSignature) {
+                log.warn("Archive signature check failed.");
+                if (!overrides
+                    .isForced(Conflict.SIGNATURE_CONFLICT)) {
+
+                    /*
+                     * Normally for import conflicts that can be overridden, we try to
+                     * report them all the first time so if the user intends to override,
+                     * they can do so with just one more request. However in the case of
+                     * a bad signature, we're going to report immediately due to the nature
+                     * of what this might mean.
+                     */
+                    throw new ImportConflictException(
+                        i18n.tr("Archive failed signature check"),
+                        Conflict.SIGNATURE_CONFLICT);
+                }
+                else {
+                    log.warn("Ignoring signature check failure.");
+                }
             }
 
             File consumerExport = new File(tmpDir, "consumer_export.zip");
@@ -265,10 +263,6 @@
             result.put("meta", m);
             return result;
         }
-//        catch (CertificateException e) {
-//            log.error("Exception caught importing archive", e);
-//            throw new ImportExtractionException("unable to extract export archive", e);
-//        }
         catch (FileNotFoundException fnfe) {
             log.error("Archive file does not contain consumer_export.zip", fnfe);
             throw new ImportExtractionException(i18n.tr("The archive does not contain " +
@@ -287,6 +281,11 @@
         catch (IOException e) {
             log.error("Exception caught importing archive", e);
             throw new ImportExtractionException("unable to extract export archive", e);
+        }
+        catch (CertificateException e) {
+            log.error("Certificate exception checking archive signature", e);
+            throw new ImportExtractionException(
+                "Certificate exception checking archive signature", e);
         }
         finally {
             if (tmpDir != null) {
```
