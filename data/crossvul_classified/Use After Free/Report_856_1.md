# CrossVul Fix Pair: Use After Free in cpp
**Pair ID:** 856_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `856_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```cpp
Lines 6-46 of the vulnerable file.

 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <folly/portability/GTest.h>
#include <memory>
#include <proxygen/lib/http/codec/compress/HeaderTable.h>
#include <proxygen/lib/http/codec/compress/Logging.h>
#include <sstream>

using namespace std;
using namespace testing;

namespace proxygen {

class HeaderTableTests : public testing::Test {
 protected:
  void xcheck(uint32_t internal, uint32_t external) {
    EXPECT_EQ(HeaderTable::toExternal(head_, length_, internal), external);
    EXPECT_EQ(HeaderTable::toInternal(head_, length_, external), internal);
  }

  uint32_t head_{0};
  uint32_t length_{0};
};

TEST_F(HeaderTableTests, index_translation) {
  // simple cases
  length_ = 10;
  head_ = 5;
  xcheck(0, 6);
  xcheck(3, 3);
  xcheck(5, 1);

  // wrap
  head_ = 1;
  xcheck(0, 2);
  xcheck(8, 4);
  xcheck(5, 7);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,6 +25,27 @@
     EXPECT_EQ(HeaderTable::toInternal(head_, length_, external), internal);
   }
 
+  void resizeTable(HeaderTable& table, uint32_t newCapacity, uint32_t newMax) {
+    table.setCapacity(newCapacity);
+    // On resizing the table size (count of headers) remains the same or sizes
+    // down; can not size up
+    EXPECT_LE(table.size(), newMax);
+  }
+
+  void resizeAndFillTable(
+      HeaderTable& table, HPACKHeader& header, uint32_t newMax,
+      uint32_t fillCount) {
+    uint32_t newCapacity = header.bytes() * newMax;
+    resizeTable(table, newCapacity, newMax);
+    // Fill the table (with one extra) and make sure we haven't violated our
+    // size (bytes) limits (expected one entry to be evicted)
+    for (size_t i = 0; i <= fillCount; ++i) {
+      EXPECT_EQ(table.add(header), true);
+    }
+    EXPECT_EQ(table.size(), newMax);
+    EXPECT_EQ(table.bytes(), newCapacity);
+  }
+
   uint32_t head_{0};
   uint32_t length_{0};
 };
@@ -94,11 +115,12 @@
   EXPECT_EQ(table.names().size(), 0);
 }
 
-TEST_F(HeaderTableTests, set_capacity) {
+TEST_F(HeaderTableTests, reduce_capacity) {
   HPACKHeader accept("accept-encoding", "gzip");
   uint32_t max = 10;
   uint32_t capacity = accept.bytes() * max;
   HeaderTable table(capacity);
+  EXPECT_GT(table.length(), max);
 
   // fill the table
   for (size_t i = 0; i < max; i++) {
@@ -167,4 +189,79 @@
 
 }
 
-}
+TEST_F(HeaderTableTests, varyCapacity) {
+  HPACKHeader accept("accept-encoding", "gzip");
+  uint32_t max = 6;
+  uint32_t capacity = accept.bytes() * max;
+  HeaderTable table(capacity);
+
+  // Fill the table (extra) and make sure we haven't violated our
+  // size (bytes) limits (expected one entry to be evicted)
+  for (size_t i = 0; i <= table.length(); ++i) {
+    EXPECT_EQ(table.add(accept), true);
+  }
+  EXPECT_EQ(table.size(), max);
+
+  // Size down the table and verify we are still honoring our size (bytes)
+  // limits
+  resizeAndFillTable(table, accept, 4, 5);
+
+  // Size up the table (in between previous max and min within test) and verify
+  // we are still horing our size (bytes) limits
+  resizeAndFillTable(table, accept, 5, 6);
+
+  // Finally reize up one last timestamps
+  resizeAndFillTable(table, accept, 8, 9);
+}
+
+TEST_F(HeaderTableTests, varyCapacityMalignHeadIndex) {
+  // Test checks for a previous bug/crash condition where due to resizing
+  // the underlying table to a size lower than a previous max but up from the
+  // current size and the position of the head_ index an out of bounds index
+  // would occur
+
+  // Initialize header table
+  HPACKHeader accept("accept-encoding", "gzip");
+  uint32_t max = 6;
+  uint32_t capacity = accept.bytes() * max;
+  HeaderTable table(capacity);
+
+  // Push head_ to last index in underlying table before potential wrap
+  // This is our max table size for the duration of the test
+  for (size_t i = 0; i < table.length(); ++i) {
+    EXPECT_EQ(table.add(accept), true);
+  }
+  EXPECT_EQ(table.size(), max);
+  EXPECT_EQ(table.bytes(), capacity);
+
+  // Flush underlying table (head_ remains the same at the previous max index)
+  // Header guranteed to cause a flush as header itself requires 32 bytes plus
+  // the sizes of the name and value anyways (which themselves would cause a
+  // flush)
+  string strLargerThanTableCapacity = string(capacity + 1, 'a');
+  HPACKHeader flush("flush", strLargerThanTableCapacity);
+  EXPECT_EQ(table.add(flush), false);
+  EXPECT_EQ(table.size(), 0);
+
+  // Now reduce capacity of table (in functional terms table.size() is lowered
+  // but currently table.length() remains the same)
+  max = 3;
+  resizeTable(table, accept.bytes() * max, max);
+
+  // Increase capacity of table (but smaller than all time max; head_ still at
+  // previous max index).  Previously (now fixed) this size up resulted in
+  // incorrect resizing semantics
+  max = 4;
+  resizeTable(table, accept.bytes() * max, max);
+
+  // Now try and add headers; there should be no crash with current position of
+  // head_ in the underlying table.  Note this is merely one possible way we
+  // could force the test to crash as a result of the resize bug this test was
+  // added for
+  for (size_t i = 0; i <= table.length(); ++i) {
+    EXPECT_EQ(table.add(accept), true);
+  }
+  EXPECT_EQ(table.size(), max);
+}
+
+}
```
