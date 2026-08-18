# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 974_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `974_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 1-23 of the vulnerable file.

/************************************************************************
**
**  Copyright (C) 2015  John Schember <john@nachtimwald.com>
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

#pragma once
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 /************************************************************************
 **
+**  Copyright (C) 2019  Kevin B. Hendricks, Stratford, Ontario Canada
 **  Copyright (C) 2015  John Schember <john@nachtimwald.com>
 **  Copyright (C) 2009, 2010, 2011  Strahinja Markovic  <strahinja.markovic@gmail.com>
 **
@@ -132,4 +133,13 @@
     EPUBLoadParseError(const std::string &msg) : std::runtime_error(msg) { };
 };
 
+
+/**
+ * Thrown for Invalid EPUB errors while loading and parsing content files.
+ */
+class UNZIPLoadParseError : public std::runtime_error {
+public:
+    UNZIPLoadParseError(const std::string &msg) : std::runtime_error(msg) { };
+};
+
 #endif // SG_EXCEPTION_H
```
