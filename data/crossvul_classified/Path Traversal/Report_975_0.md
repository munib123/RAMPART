# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in cpp
**Pair ID:** 975_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `975_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```cpp
Lines 407-447 of the vulnerable file.


    res = unzGoToFirstFile(zfile);

    if (res == UNZ_OK) {
        do {
            // Get the name of the file in the archive.
            char file_name[MAX_PATH] = {0};
            unz_file_info64 file_info;
            unzGetCurrentFileInfo64(zfile, &file_info, file_name, MAX_PATH, NULL, 0, NULL, 0);
            QString qfile_name;
            QString cp437_file_name;
            qfile_name = QString::fromUtf8(file_name);
            if (!(file_info.flag & (1<<11))) {
                // General purpose bit 11 says the filename is utf-8 encoded. If not set then
                // IBM 437 encoding might be used.
                cp437_file_name = cp437->toUnicode(file_name);
            }

            // If there is no file name then we can't do anything with it.
            if (!qfile_name.isEmpty()) {
                // We use the dir object to create the path in the temporary directory.
                // Unfortunately, we need a dir ojbect to do this as it's not a static function.
                QDir dir(m_ExtractedFolderPath);
                // Full file path in the temporary directory.
                QString file_path = m_ExtractedFolderPath + "/" + qfile_name;
                QFileInfo qfile_info(file_path);

                // Is this entry a directory?
                if (file_info.uncompressed_size == 0 && qfile_name.endsWith('/')) {
                    dir.mkpath(qfile_name);
                    continue;
                } else {
                    dir.mkpath(qfile_info.path());
		    // add it to the list of files found inside the zip
		    if (cp437_file_name.isEmpty()) {
		        m_ZipFilePaths << qfile_name;
		    } else {
                        m_ZipFilePaths << cp437_file_name;
		    }
                }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -424,6 +424,14 @@
 
             // If there is no file name then we can't do anything with it.
             if (!qfile_name.isEmpty()) {
+
+	        // for security reasons we need the file path to always be inside the 
+                // target folder and not outside, so we will remove all relative upward 
+                // paths segments ".." from the file path before prepending the target 
+                // folder to create the final target path
+	        qfile_name = qfile_name.replace("../","");
+                cp437_file_name = cp437_file_name.replace("../","");
+
                 // We use the dir object to create the path in the temporary directory.
                 // Unfortunately, we need a dir ojbect to do this as it's not a static function.
                 QDir dir(m_ExtractedFolderPath);
```
