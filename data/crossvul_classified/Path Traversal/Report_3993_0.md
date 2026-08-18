# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in java
**Pair ID:** 3993_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3993_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```java
Lines 71-111 of the vulnerable file.


        if (presDir != null) {
            if (msg.downloadable) {
                String fileExt = FilenameUtils.getExtension(msg.presFilename);
                File presFile = new File(presDir.getAbsolutePath() + File.separatorChar + msg.presId + "." + fileExt);
                log.info("Make file downloadable. {}", downloadableFile.getAbsolutePath());
                copyPresentationFile(presFile, downloadableFile);
            } else {
                if (downloadableFile.exists()) {
                    if(downloadableFile.delete()) {
                        log.info("File deleted. {}", downloadableFile.getAbsolutePath());
                    } else {
                        log.warn("Failed to delete. {}", downloadableFile.getAbsolutePath());
                    }
                }
            }
        }
    }

    public File getDownloadablePresentationFile(String meetingId, String presId, String presFilename) {
    	log.info("Find downloadable presentation for meetingId={} presId={} filename={}", meetingId, presId, presFilename);

        File presDir = Util.getPresentationDir(presentationBaseDir, meetingId, presId);
        return new File(presDir.getAbsolutePath() + File.separatorChar + presFilename);
    }

    public void kickOffRecordingChapterBreak(String meetingId, Long timestamp) {
        String done = recordStatusDir + File.separatorChar + meetingId + "-" + timestamp + ".done";

        File doneFile = new File(done);
        if (!doneFile.exists()) {
            try {
                doneFile.createNewFile();
                if (!doneFile.exists())
                    log.error("Failed to create {} file.", done);
            } catch (IOException e) {
                log.error("Exception occured when trying to create {} file", done);
            }
        } else {
            log.error("{} file already exists.", done);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,10 +88,28 @@
     }
 
     public File getDownloadablePresentationFile(String meetingId, String presId, String presFilename) {
-    	log.info("Find downloadable presentation for meetingId={} presId={} filename={}", meetingId, presId, presFilename);
-
+        log.info("Find downloadable presentation for meetingId={} presId={} filename={}", meetingId, presId,
+                presFilename);
         File presDir = Util.getPresentationDir(presentationBaseDir, meetingId, presId);
-        return new File(presDir.getAbsolutePath() + File.separatorChar + presFilename);
+        // Build file to presFilename
+        // Get canonicalPath and make sure it starts with
+        // /var/bigbluebutton/<meetingid-pattern>
+        // If so return file, if not return null
+        File presFile = new File(presDir.getAbsolutePath() + File.separatorChar + presFilename);
+        try {
+            String presFileCanonical = presFile.getCanonicalPath();
+            log.debug("Requested presentation name file full path {}",presFileCanonical);
+            if (presFileCanonical.startsWith(presentationBaseDir)) {
+                return presFile;
+            }
+        } catch (IOException e) {
+            log.error("Exception getting canonical path for {}.\n{}", presFilename, e);
+            return null;
+        }
+
+        log.error("Cannot find file for {}.", presFilename);
+
+        return null;
     }
 
     public void kickOffRecordingChapterBreak(String meetingId, Long timestamp) {
```
