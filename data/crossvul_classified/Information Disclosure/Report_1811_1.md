# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 1811_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1811_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 512-552 of the vulnerable file.


        switch (mLacing) {
          case LACING_XIPH:
            for (Index=0; Index<FrameNum; Index++) {
              // get the size of the frame
              FrameSize = 0;
              uint8 Value;
              do {
                Value = Mem.GetUInt8();
                FrameSize += Value;
                LastBufferSize--;
              } while (Value == 0xFF);
              SizeList[Index] = FrameSize;
              LastBufferSize -= FrameSize;
            }
            SizeList[Index] = LastBufferSize;
            break;
          case LACING_EBML:
            SizeRead = LastBufferSize;
            FrameSize = ReadCodedSizeValue(BufferStart + Mem.GetPosition(), SizeRead, SizeUnknown);
            SizeList[0] = FrameSize;
            Mem.Skip(SizeRead);
            LastBufferSize -= FrameSize + SizeRead;

            for (Index=1; Index<FrameNum; Index++) {
              // get the size of the frame
              SizeRead = LastBufferSize;
              FrameSize += ReadCodedSizeSignedValue(BufferStart + Mem.GetPosition(), SizeRead, SizeUnknown);
              SizeList[Index] = FrameSize;
              Mem.Skip(SizeRead);
              LastBufferSize -= FrameSize + SizeRead;
            }
            if (Index <= FrameNum) // Safety check if FrameNum == 0
              SizeList[Index] = LastBufferSize;
            break;
          case LACING_FIXED:
            for (Index=0; Index<=FrameNum; Index++) {
              // get the size of the frame
              SizeList[Index] = LastBufferSize / (FrameNum + 1);
            }
            break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -529,6 +529,8 @@
           case LACING_EBML:
             SizeRead = LastBufferSize;
             FrameSize = ReadCodedSizeValue(BufferStart + Mem.GetPosition(), SizeRead, SizeUnknown);
+            if (!FrameSize || (static_cast<uint32>(FrameSize + SizeRead) > LastBufferSize))
+              throw SafeReadIOCallback::EndOfStreamX(SizeRead);
             SizeList[0] = FrameSize;
             Mem.Skip(SizeRead);
             LastBufferSize -= FrameSize + SizeRead;
@@ -537,6 +539,8 @@
               // get the size of the frame
               SizeRead = LastBufferSize;
               FrameSize += ReadCodedSizeSignedValue(BufferStart + Mem.GetPosition(), SizeRead, SizeUnknown);
+              if (!FrameSize || (static_cast<uint32>(FrameSize + SizeRead) > LastBufferSize))
+                throw SafeReadIOCallback::EndOfStreamX(SizeRead);
               SizeList[Index] = FrameSize;
               Mem.Skip(SizeRead);
               LastBufferSize -= FrameSize + SizeRead;
```
