# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 3594_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3594_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 278-318 of the vulnerable file.


////////////////////////////////////////////////////////////////////////////////
// protected members
////////////////////////////////////////////////////////////////////////////////

void Ogg::XiphComment::parse(const ByteVector &data)
{
  // The first thing in the comment data is the vendor ID length, followed by a
  // UTF8 string with the vendor ID.

  int pos = 0;

  int vendorLength = data.mid(0, 4).toUInt(false);
  pos += 4;

  d->vendorID = String(data.mid(pos, vendorLength), String::UTF8);
  pos += vendorLength;

  // Next the number of fields in the comment vector.

  int commentFields = data.mid(pos, 4).toUInt(false);
  pos += 4;

  for(int i = 0; i < commentFields; i++) {

    // Each comment field is in the format "KEY=value" in a UTF8 string and has
    // 4 bytes before the text starts that gives the length.

    int commentLength = data.mid(pos, 4).toUInt(false);
    pos += 4;

    String comment = String(data.mid(pos, commentLength), String::UTF8);
    pos += commentLength;

    int commentSeparatorPosition = comment.find("=");

    String key = comment.substr(0, commentSeparatorPosition);
    String value = comment.substr(commentSeparatorPosition + 1);

    addField(key, value, false);
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -295,21 +295,31 @@
 
   // Next the number of fields in the comment vector.
 
-  int commentFields = data.mid(pos, 4).toUInt(false);
+  uint commentFields = data.mid(pos, 4).toUInt(false);
   pos += 4;
 
-  for(int i = 0; i < commentFields; i++) {
+  if(commentFields > (data.size() - 8) / 4) {
+    return;
+  }
+
+  for(uint i = 0; i < commentFields; i++) {
 
     // Each comment field is in the format "KEY=value" in a UTF8 string and has
     // 4 bytes before the text starts that gives the length.
 
-    int commentLength = data.mid(pos, 4).toUInt(false);
+    uint commentLength = data.mid(pos, 4).toUInt(false);
     pos += 4;
 
     String comment = String(data.mid(pos, commentLength), String::UTF8);
     pos += commentLength;
+    if(pos > data.size()) {
+      break;
+    }
 
     int commentSeparatorPosition = comment.find("=");
+    if(commentSeparatorPosition == -1) {
+      break;
+    }
 
     String key = comment.substr(0, commentSeparatorPosition);
     String value = comment.substr(commentSeparatorPosition + 1);
```
