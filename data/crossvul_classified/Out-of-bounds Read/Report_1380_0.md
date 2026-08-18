# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 1380_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1380_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 49-89 of the vulnerable file.


bool OutputFile::close() {
  invokeFiltersOnClose();
  return closeImpl();
}

bool OutputFile::closeImpl() {
  *s_pcloseRet = 0;
  if (!isClosed()) {
    setIsClosed(true);
    return true;
  }
  return false;
}

///////////////////////////////////////////////////////////////////////////////
// virtual functions

int64_t OutputFile::readImpl(char* /*buffer*/, int64_t /*length*/) {
  raise_warning("cannot read from a php://output stream");
  return -1;
}

int OutputFile::getc() {
  raise_warning("cannot read from a php://output stream");
  return -1;
}

int64_t OutputFile::writeImpl(const char *buffer, int64_t length) {
  assertx(length > 0);
  if (isClosed()) return 0;
  g_context->write(buffer, length);
  return length;
}

bool OutputFile::seek(int64_t /*offset*/, int /*whence*/ /* = SEEK_SET */) {
  raise_warning("cannot seek a php://output stream");
  return false;
}

int64_t OutputFile::tell() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,7 +66,7 @@
 
 int64_t OutputFile::readImpl(char* /*buffer*/, int64_t /*length*/) {
   raise_warning("cannot read from a php://output stream");
-  return -1;
+  return 0;
 }
 
 int OutputFile::getc() {
```
