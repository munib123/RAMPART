# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 1834_3
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1834_3`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 10-50 of the vulnerable file.

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  MagickCore version methods.
*/
#ifndef _MAGICKCORE_VERSION_H
#define _MAGICKCORE_VERSION_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

/*
  Define declarations.
*/
#define MagickPackageName "ImageMagick"
#define MagickCopyright  "Copyright (C) 1999-2015 ImageMagick Studio LLC"
#define MagickSVNRevision  "18658:18662M"
#define MagickLibVersion  0x700
#define MagickLibVersionText  "7.0.0"
#define MagickLibVersionNumber  0,0,0
#define MagickLibAddendum  "-0"
#define MagickLibInterface  0
#define MagickLibMinInterface  0
#if defined(_WINDOWS)
#  if defined(_WIN64)
#    define MagickPlatform "x64"
#  else
#    define MagickPlatform "x86"
#  endif
#else
#define MagickPlatform  "x86_64"
#endif
#define MagickppLibVersionText  "7.0.0"
#define MagickppLibVersionNumber  0:0:0
#define MagickppLibAddendum  "-0"
#define MagickppLibInterface  0
#define MagickppLibMinInterface  0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 */
 #define MagickPackageName "ImageMagick"
 #define MagickCopyright  "Copyright (C) 1999-2015 ImageMagick Studio LLC"
-#define MagickSVNRevision  "18658:18662M"
+#define MagickSVNRevision  "18670M"
 #define MagickLibVersion  0x700
 #define MagickLibVersionText  "7.0.0"
 #define MagickLibVersionNumber  0,0,0
@@ -48,12 +48,12 @@
 #define MagickppLibAddendum  "-0"
 #define MagickppLibInterface  0
 #define MagickppLibMinInterface  0
-#define MagickReleaseDate  "2015-05-26"
+#define MagickReleaseDate  "2015-05-29"
 #define MagickChangeDate   "20120427"
 #define MagickAuthoritativeLicense  \
   "http://www.imagemagick.org/script/license.php"
 #define MagickAuthoritativeURL  "http://www.imagemagick.org"
-#define MagickFeatures "DPC HDRI OpenMP"
+#define MagickFeatures "DPC HDRI Cipher OpenMP"
 #define MagickDelegates "bzlib djvu mpeg fftw fpx fontconfig freetype jbig jng jpeg lcms lzma openexr pango png ps tiff webp x xml zlib"
 #define MagickHomeURL  "file:///usr/local/share/doc/ImageMagick-7/index.html"
 #if (MAGICKCORE_QUANTUM_DEPTH == 8)
```
