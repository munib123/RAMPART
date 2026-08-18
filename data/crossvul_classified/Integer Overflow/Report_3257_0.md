# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 3257_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3257_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 183-213 of the vulnerable file.

{
  bool down = is->readU8();
  is->skip(2);
  rdr::U32 key = is->readU32();
  handler->keyEvent(key, down);
}

void SMsgReader::readPointerEvent()
{
  int mask = is->readU8();
  int x = is->readU16();
  int y = is->readU16();
  handler->pointerEvent(Point(x, y), mask);
}


void SMsgReader::readClientCutText()
{
  is->skip(3);
  int len = is->readU32();
  if (len > maxCutText) {
    is->skip(len);
    vlog.error("Cut text too long (%d bytes) - ignoring", len);
    return;
  }
  CharArray ca(len+1);
  ca.buf[len] = 0;
  is->readBytes(ca.buf, len);
  handler->clientCutText(ca.buf, len);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -200,6 +200,9 @@
 {
   is->skip(3);
   int len = is->readU32();
+  if (len < 0) {
+    throw Exception("Cut text too long.");
+  }
   if (len > maxCutText) {
     is->skip(len);
     vlog.error("Cut text too long (%d bytes) - ignoring", len);
```
