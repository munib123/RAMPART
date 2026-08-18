# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1523_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1523_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 99-139 of the vulnerable file.


  KJ_DISALLOW_COPY(ReadLimiter);
};

#if !CAPNP_LITE
class BrokenCapFactory {
  // Callback for constructing broken caps.  We use this so that we can avoid arena.c++ having a
  // link-time dependency on capability code that lives in libcapnp-rpc.

public:
  virtual kj::Own<ClientHook> newBrokenCap(kj::StringPtr description) = 0;
};
#endif  // !CAPNP_LITE

class SegmentReader {
public:
  inline SegmentReader(Arena* arena, SegmentId id, kj::ArrayPtr<const word> ptr,
                       ReadLimiter* readLimiter);

  KJ_ALWAYS_INLINE(bool containsInterval(const void* from, const void* to));

  inline Arena* getArena();
  inline SegmentId getSegmentId();

  inline const word* getStartPtr();
  inline WordCount getOffsetTo(const word* ptr);
  inline WordCount getSize();

  inline kj::ArrayPtr<const word> getArray();

  inline void unread(WordCount64 amount);
  // Add back some words to the ReadLimiter.

private:
  Arena* arena;
  SegmentId id;
  kj::ArrayPtr<const word> ptr;
  ReadLimiter* readLimiter;

  KJ_DISALLOW_COPY(SegmentReader);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,6 +117,13 @@
 
   KJ_ALWAYS_INLINE(bool containsInterval(const void* from, const void* to));
 
+  KJ_ALWAYS_INLINE(bool amplifiedRead(WordCount virtualAmount));
+  // Indicates that the reader should pretend that `virtualAmount` additional data was read even
+  // though no actual pointer was traversed. This is used e.g. when reading a struct list pointer
+  // where the element sizes are zero -- the sender could set the list size arbitrarily high and
+  // cause the receiver to iterate over this list even though the message itself is small, so we
+  // need to defend agaisnt DoS attacks based on this.
+
   inline Arena* getArena();
   inline SegmentId getSegmentId();
 
@@ -365,6 +372,10 @@
           intervalLength(reinterpret_cast<const byte*>(from),
                          reinterpret_cast<const byte*>(to)) / BYTES_PER_WORD,
           arena);
+}
+
+inline bool SegmentReader::amplifiedRead(WordCount virtualAmount) {
+  return readLimiter->canRead(virtualAmount, arena);
 }
 
 inline Arena* SegmentReader::getArena() { return arena; }
```
