# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in cpp
**Pair ID:** 974_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `974_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```cpp
Lines 1-23 of the vulnerable file.

/************************************************************************
**
**  Copyright (C) 2009, 2010, 2011  Strahinja Markovic  <strahinja.markovic@gmail.com>
**
**  This file is part of Sigil.
**
**  Sigil is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  Sigil is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with Sigil.  If not, see <http://www.gnu.org/licenses/>.
**
*************************************************************************/

#ifdef _WIN32
#define NOMINMAX
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 /************************************************************************
 **
+**  Copyright (C) 2019   Kevin B. Hendricks, Stratford, Ontario Canada
 **  Copyright (C) 2009, 2010, 2011  Strahinja Markovic  <strahinja.markovic@gmail.com>
 **
 **  This file is part of Sigil.
@@ -715,6 +716,44 @@
 
             // If there is no file name then we can't do anything with it.
             if (!qfile_name.isEmpty()) {
+
+	        // for security reasons against maliciously crafted zip archives
+	        // we need the file path to always be inside the target folder 
+	        // and not outside, so we will remove all illegal backslashes
+	        // and all relative upward paths segments "/../" from the zip's local 
+	        // file name/path before prepending the target folder to create 
+	        // the final path
+
+	        QString original_path = qfile_name;
+	        bool evil_or_corrupt_epub = false;
+
+	        if (qfile_name.contains("\\")) evil_or_corrupt_epub = true; 
+	        qfile_name = "/" + qfile_name.replace("\\","");
+
+	        if (qfile_name.contains("/../")) evil_or_corrupt_epub = true;
+	        qfile_name = qfile_name.replace("/../","/");
+
+	        while(qfile_name.startsWith("/")) { 
+		  qfile_name = qfile_name.remove(0,1);
+	        }
+                
+	        if (cp437_file_name.contains("\\")) evil_or_corrupt_epub = true; 
+	        cp437_file_name = "/" + cp437_file_name.replace("\\","");
+
+	        if (cp437_file_name.contains("/../")) evil_or_corrupt_epub = true;
+	        cp437_file_name = cp437_file_name.replace("/../","/");
+
+	        while(cp437_file_name.startsWith("/")) { 
+		  cp437_file_name = cp437_file_name.remove(0,1);
+	        }
+
+	        if (evil_or_corrupt_epub) {
+		    unzCloseCurrentFile(zfile);
+		    unzClose(zfile);
+		    // throw (UNZIPLoadParseError(QString(QObject::tr("Possible evil or corrupt zip file name: %1")).arg(original_path).toStdString()));
+                    return false;
+	        }
+
                 // We use the dir object to create the path in the temporary directory.
                 // Unfortunately, we need a dir ojbect to do this as it's not a static function.
                 // Full file path in the temporary directory.
```
