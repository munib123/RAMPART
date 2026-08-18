# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in cpp
**Pair ID:** 1367_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1367_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```cpp
Lines 1-43 of the vulnerable file.

// ***************************************************************** -*- C++ -*-
/*
 * Copyright (C) 2004-2018 Exiv2 authors
 * This program is part of the Exiv2 distribution.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, 5th Floor, Boston, MA 02110-1301 USA.
 */

/*
  File:      jp2image.cpp
*/

// *****************************************************************************

// included header files
#include "config.h"

#include "jp2image.hpp"
#include "tiffimage.hpp"
#include "image.hpp"
#include "image_int.hpp"
#include "basicio.hpp"
#include "error.hpp"
#include "futils.hpp"
#include "types.hpp"
#include "safe_op.hpp"

// + standard includes
#include <string>
#include <cstring>
#include <iostream>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,10 +18,6 @@
  * Foundation, Inc., 51 Franklin Street, 5th Floor, Boston, MA 02110-1301 USA.
  */
 
-/*
-  File:      jp2image.cpp
-*/
-
 // *****************************************************************************
 
 // included header files
@@ -197,6 +193,16 @@
         return result;
     }
 
+static void boxes_check(size_t b,size_t m)
+{
+    if ( b > m ) {
+#ifdef EXIV2_DEBUG_MESSAGES
+        std::cout << "Exiv2::Jp2Image::readMetadata box maximum exceeded" << std::endl;
+#endif
+        throw Error(kerCorruptedMetadata);
+    }
+}
+
     void Jp2Image::readMetadata()
     {
 #ifdef EXIV2_DEBUG_MESSAGES
@@ -219,9 +225,12 @@
         Jp2BoxHeader      subBox    = {0,0};
         Jp2ImageHeaderBox ihdr      = {0,0,0,0,0,0,0,0};
         Jp2UuidBox        uuid      = {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
+        size_t            boxes     = 0 ;
+        size_t            boxem     = 1000 ; // boxes max
 
         while (io_->read((byte*)&box, sizeof(box)) == sizeof(box))
         {
+            boxes_check(boxes++,boxem );
             position   = io_->tell();
             box.length = getLong((byte*)&box.length, bigEndian);
             box.type   = getLong((byte*)&box.type, bigEndian);
@@ -251,8 +260,12 @@
 
                     while (io_->read((byte*)&subBox, sizeof(subBox)) == sizeof(subBox) && subBox.length )
                     {
+                        boxes_check(boxes++, boxem) ;
                         subBox.length = getLong((byte*)&subBox.length, bigEndian);
                         subBox.type   = getLong((byte*)&subBox.type, bigEndian);
+                        if (subBox.length > io_->size() ) {
+                            throw Error(kerCorruptedMetadata);
+                        }
 #ifdef EXIV2_DEBUG_MESSAGES
                         std::cout << "Exiv2::Jp2Image::readMetadata: "
                         << "subBox = " << toAscii(subBox.type) << " length = " << subBox.length << std::endl;
@@ -308,7 +321,9 @@
                         }
 
                         io_->seek(restore,BasicIo::beg);
-                        io_->seek(subBox.length, Exiv2::BasicIo::cur);
+                        if ( io_->seek(subBox.length, Exiv2::BasicIo::cur) != 0 ) {
+                            throw Error(kerCorruptedMetadata);
+                        }
                         restore = io_->tell();
                     }
                     break;
```
