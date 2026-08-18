# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 656_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `656_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 30-71 of the vulnerable file.

#include "inc/GlyphCache.h"
#include "inc/CachedFace.h"
#include "inc/CmapCache.h"
#include "inc/Silf.h"
#include "inc/json.h"

using namespace graphite2;

#if !defined GRAPHITE2_NTRACING
extern json *global_log;
#endif

namespace
{
    bool load_face(Face & face, unsigned int options)
    {
#ifdef GRAPHITE2_TELEMETRY
        telemetry::category _misc_cat(face.tele.misc);
#endif
        Face::Table silf(face, Tag::Silf, 0x00050000);
        if (silf)   options &= ~gr_face_dumbRendering;
        else if (!(options &  gr_face_dumbRendering))
            return false;

        if (!face.readGlyphs(options))
            return false;

        if (silf)
        {
            if (!face.readFeatures() || !face.readGraphite(silf))
            {
#if !defined GRAPHITE2_NTRACING
                if (global_log)
                {
                    *global_log << json::object
                        << "type" << "fontload"
                        << "failure" << face.error()
                        << "context" << face.error_context()
                    << json::close;
                }
#endif
                return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,8 +47,7 @@
         telemetry::category _misc_cat(face.tele.misc);
 #endif
         Face::Table silf(face, Tag::Silf, 0x00050000);
-        if (silf)   options &= ~gr_face_dumbRendering;
-        else if (!(options &  gr_face_dumbRendering))
+        if (!silf)
             return false;
 
         if (!face.readGlyphs(options))
@@ -74,7 +73,7 @@
                 return true;
         }
         else
-            return options & gr_face_dumbRendering;
+            return false;
     }
 }
 
```
