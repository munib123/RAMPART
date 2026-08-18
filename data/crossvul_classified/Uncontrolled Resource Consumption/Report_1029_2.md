# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1029_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1029_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 440-480 of the vulnerable file.

   *
   * @param key specifies the name of the header to set; it WILL NOT be copied.
   * @param value specifies the value of the header to set; it WILL NOT be copied.
   */
  virtual void setReference(const LowerCaseString& key, const std::string& value) PURE;

  /**
   * Set a header with a reference key in the map. The key MUST point to point to data that will
   * live beyond the lifetime of any request/response using the string (since a codec may optimize
   * for zero copy). The value will be copied.
   *
   * Calling setReferenceKey multiple times for the same header will result in only the last header
   * being present in the HeaderMap.
   *
   * @param key specifies the name of the header to set; it WILL NOT be copied.
   * @param value specifies the value of the header to set; it WILL be copied.
   */
  virtual void setReferenceKey(const LowerCaseString& key, const std::string& value) PURE;

  /**
   * @return uint64_t the approximate size of the header map in bytes.
   */
  virtual uint64_t byteSize() const PURE;

  /**
   * Get a header by key.
   * @param key supplies the header key.
   * @return the header entry if it exists otherwise nullptr.
   */
  virtual const HeaderEntry* get(const LowerCaseString& key) const PURE;
  virtual HeaderEntry* get(const LowerCaseString& key) PURE;

  // aliases to make iterate() and iterateReverse() callbacks easier to read
  enum class Iterate { Continue, Break };

  /**
   * Callback when calling iterate() over a const header map.
   * @param header supplies the header entry.
   * @param context supplies the context passed to iterate().
   * @return Iterate::Continue to continue iteration.
   */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -457,9 +457,41 @@
   virtual void setReferenceKey(const LowerCaseString& key, const std::string& value) PURE;
 
   /**
+   * HeaderMap contains an internal byte size count, updated as entries are added, removed, or
+   * modified through the HeaderMap interface. However, HeaderEntries can be accessed and modified
+   * by reference so that the HeaderMap can no longer accurately update the internal byte size
+   * count.
+   *
+   * Calling byteSize before a HeaderEntry is accessed will return the internal byte size count. The
+   * value is cleared when a HeaderEntry is accessed, and the value is updated and set again when
+   * refreshByteSize is called.
+   *
+   * To guarantee an accurate byte size count, call refreshByteSize.
+   *
+   * @return uint64_t the approximate size of the header map in bytes if valid.
+   */
+  virtual absl::optional<uint64_t> byteSize() const PURE;
+
+  /**
+   * This returns the sum of the byte sizes of the keys and values in the HeaderMap. This also
+   * updates and sets the byte size count.
+   *
+   * To guarantee an accurate byte size count, use this. If it is known HeaderEntries have not been
+   * manipulated since a call to refreshByteSize, it is safe to use byteSize.
+   *
    * @return uint64_t the approximate size of the header map in bytes.
    */
-  virtual uint64_t byteSize() const PURE;
+  virtual uint64_t refreshByteSize() PURE;
+
+  /**
+   * This returns the sum of the byte sizes of the keys and values in the HeaderMap.
+   *
+   * This iterates over the HeaderMap to calculate size and should only be called directly when the
+   * user wants an explicit recalculation of the byte size.
+   *
+   * @return uint64_t the approximate size of the header map in bytes.
+   */
+  virtual uint64_t byteSizeInternal() const PURE;
 
   /**
    * Get a header by key.
```
