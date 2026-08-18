# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 1380_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1380_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 78-118 of the vulnerable file.

}

bool BZ2File::flush() {
  assertx(m_bzFile);
  return BZ2_bzflush(m_bzFile);
}

int64_t BZ2File::readImpl(char * buf, int64_t length) {
  if (length == 0) {
    return 0;
  }
  assertx(m_bzFile);
  int len = BZ2_bzread(m_bzFile, buf, length);
  /* Sometimes libbz2 will return fewer bytes than requested, and set bzerror
   * to BZ_STREAM_END, but it's not actually EOF, and you can keep reading from
   * the file - so, only set EOF after a failed read. This matches PHP5.
   */
  if (len <= 0) {
    setEof(true);
    if (len < 0) {
      return -1;
    }
  }
  return len;
}

int64_t BZ2File::writeImpl(const char * buf, int64_t length) {
  assertx(m_bzFile);
  return BZ2_bzwrite(m_bzFile, (char *)buf, length);
}

bool BZ2File::closeImpl() {
  if (!isClosed()) {
    if (m_bzFile) {
      BZ2_bzclose(m_bzFile);
      m_bzFile = nullptr;
    }
    setIsClosed(true);
    if (m_innerFile) {
      m_innerFile->close();
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,7 +95,7 @@
   if (len <= 0) {
     setEof(true);
     if (len < 0) {
-      return -1;
+      return 0;
     }
   }
   return len;
```
