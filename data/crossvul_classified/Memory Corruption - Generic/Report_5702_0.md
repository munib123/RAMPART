# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in scala
**Pair ID:** 5702_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5702_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```scala
Lines 367-407 of the vulnerable file.

          val end = if (i == curSegmentIdx) cur else s.length+1
          parts = (start, end, s) :: parts
          i = i-1
        }
        val len = parts.map(p => p._2 - p._1 - 1).foldLeft(0)(_ + _)
        val chars = new Array[Char](len)
        i = 0
        var pos = 0

        while (i < parts.size) {
          val (start, end, b) = parts(i)
          val partLen = end-start-1
          System.arraycopy(b, start, chars, pos, partLen)
          pos = pos + partLen
          i = i+1
        }
        new String(chars)
      }
    }

    def near = new String(segment, (cur-20) max 0, (cur + 1) min Segments.segmentSize)

    def release = segments.foreach(Segments.release)

    private[JsonParser] def automaticClose = if (closeAutomatically) in.close

    private[this] def read = {
      if (offset >= segment.length) {
        val newSegment = Segments.apply()
        offset = 0
        segment = newSegment.seg
        segments = segments ::: List(newSegment)
        curSegmentIdx = segments.length - 1
      }

      val length = in.read(segment, offset, segment.length-offset)
      if (length != -1) {
        cur = offset
        offset += length
        length
      } else -1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -384,7 +384,11 @@
       }
     }
 
-    def near = new String(segment, (cur-20) max 0, (cur + 1) min Segments.segmentSize)
+    def near = {
+      val start = (cur - 20) max 0
+      val len = ((cur + 1) min Segments.segmentSize) - start
+      new String(segment, start, len)
+    }
 
     def release = segments.foreach(Segments.release)
 
```
