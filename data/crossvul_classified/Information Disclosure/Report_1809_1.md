# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 1809_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1809_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 29-69 of the vulnerable file.

**********************************************************************/

/*!
  \file
  \version \$Id$
  \author Steve Lhomme     <robux4 @ users.sf.net>
  \author Jory Stone       <jcsston @ toughguy.net>
*/

#include <cassert>

#if __GNUC__ == 2 && ! defined ( __OpenBSD__ )
#include <wchar.h>
#endif

#include "ebml/EbmlUnicodeString.h"

START_LIBEBML_NAMESPACE

// ===================== UTFstring class ===================

UTFstring::UTFstring()
  :_Length(0)
  ,_Data(NULL)
{}

UTFstring::UTFstring(const wchar_t * _aBuf)
  :_Length(0)
  ,_Data(NULL)
{
  *this = _aBuf;
}

UTFstring::UTFstring(std::wstring const &_aBuf)
  :_Length(0)
  ,_Data(NULL)
{
  *this = _aBuf.c_str();
}

UTFstring::~UTFstring()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,6 +46,21 @@
 START_LIBEBML_NAMESPACE
 
 // ===================== UTFstring class ===================
+
+static unsigned int UTFCharLength(uint8 lead)
+{
+  if (lead < 0x80)
+    return 1;
+  else if ((lead >> 5) == 0x6)
+    return 2;
+  else if ((lead >> 4) == 0xe)
+    return 3;
+  else if ((lead >> 3) == 0x1e)
+    return 4;
+  else
+    // Invalid size?
+    return 0;
+}
 
 UTFstring::UTFstring()
   :_Length(0)
@@ -143,39 +158,39 @@
   delete [] _Data;
   // find the size of the final UCS-2 string
   size_t i;
-  for (_Length=0, i=0; i<UTF8string.length(); _Length++) {
-    uint8 lead = static_cast<uint8>(UTF8string[i]);
-    if (lead < 0x80)
-      i++;
-    else if ((lead >> 5) == 0x6)
-      i += 2;
-    else if ((lead >> 4) == 0xe)
-      i += 3;
-    else if ((lead >> 3) == 0x1e)
-      i += 4;
+  const size_t SrcLength = UTF8string.length();
+  for (_Length=0, i=0; i<SrcLength; _Length++) {
+    const unsigned int CharLength = UTFCharLength(static_cast<uint8>(UTF8string[i]));
+    if ((CharLength >= 1) && (CharLength <= 4))
+      i += CharLength;
     else
       // Invalid size?
       break;
   }
   _Data = new wchar_t[_Length+1];
   size_t j;
-  for (j=0, i=0; i<UTF8string.length(); j++) {
-    uint8 lead = static_cast<uint8>(UTF8string[i]);
-    if (lead < 0x80) {
-      _Data[j] = lead;
-      i++;
-    } else if ((lead >> 5) == 0x6) {
-      _Data[j] = ((lead & 0x1F) << 6) + (UTF8string[i+1] & 0x3F);
-      i += 2;
-    } else if ((lead >> 4) == 0xe) {
-      _Data[j] = ((lead & 0x0F) << 12) + ((UTF8string[i+1] & 0x3F) << 6) + (UTF8string[i+2] & 0x3F);
-      i += 3;
-    } else if ((lead >> 3) == 0x1e) {
-      _Data[j] = ((lead & 0x07) << 18) + ((UTF8string[i+1] & 0x3F) << 12) + ((UTF8string[i+2] & 0x3F) << 6) + (UTF8string[i+3] & 0x3F);
-      i += 4;
-    } else
+  for (j=0, i=0; i<SrcLength; j++) {
+    const uint8 lead              = static_cast<uint8>(UTF8string[i]);
+    const unsigned int CharLength = UTFCharLength(lead);
+    if ((CharLength < 1) || (CharLength > 4))
       // Invalid char?
       break;
+
+    if ((i + CharLength) > SrcLength)
+      // Guard against invalid memory access beyond the end of the
+      // source buffer.
+      break;
+
+    if (CharLength == 1)
+      _Data[j] = lead;
+    else if (CharLength == 2)
+      _Data[j] = ((lead & 0x1F) << 6) + (UTF8string[i+1] & 0x3F);
+    else if (CharLength == 3)
+      _Data[j] = ((lead & 0x0F) << 12) + ((UTF8string[i+1] & 0x3F) << 6) + (UTF8string[i+2] & 0x3F);
+    else if (CharLength == 4)
+      _Data[j] = ((lead & 0x07) << 18) + ((UTF8string[i+1] & 0x3F) << 12) + ((UTF8string[i+2] & 0x3F) << 6) + (UTF8string[i+3] & 0x3F);
+
+    i += CharLength;
   }
   _Data[j] = 0;
 }
```
