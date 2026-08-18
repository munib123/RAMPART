# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 1382_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1382_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 98-138 of the vulnerable file.

  addToQueue("1603010000aa");
  EXPECT_ANY_THROW(read_.read(queue_));
}

TEST_F(PlaintextRecordTest, TestDataRemaining) {
  addToQueue("16030100050123456789160301");
  auto msg = read_.read(queue_);
  EXPECT_EQ(msg->type, ContentType::handshake);
  expectSame(msg->fragment, "0123456789");
  EXPECT_EQ(queue_.chainLength(), 3);
  expectSame(queue_.move(), "160301");
}

TEST_F(PlaintextRecordTest, TestSkipAndWait) {
  read_.setSkipEncryptedRecords(true);
  addToQueue("17030100050123456789");
  EXPECT_FALSE(read_.read(queue_).hasValue());
  EXPECT_TRUE(queue_.empty());
}

TEST_F(PlaintextRecordTest, TestWaitBeforeSkip) {
  read_.setSkipEncryptedRecords(true);
  addToQueue("170301000501234567");
  EXPECT_FALSE(read_.read(queue_).hasValue());
  expectSame(queue_.move(), "170301000501234567");
}

TEST_F(PlaintextRecordTest, TestSkipAndRead) {
  read_.setSkipEncryptedRecords(true);
  addToQueue("170301000501234567891703010005012345678916030100050123456789");
  auto msg = read_.read(queue_);
  EXPECT_EQ(msg->type, ContentType::handshake);
  expectSame(msg->fragment, "0123456789");
  EXPECT_TRUE(queue_.empty());
}

TEST_F(PlaintextRecordTest, TestWriteHandshake) {
  TLSMessage msg{ContentType::handshake, getBuf("1234567890")};
  auto buf = write_.write(std::move(msg));
  expectSame(buf.data, "16030300051234567890");
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,6 +115,16 @@
   EXPECT_TRUE(queue_.empty());
 }
 
+TEST_F(PlaintextRecordTest, TestSkipOversizedRecord) {
+  read_.setSkipEncryptedRecords(true);
+  addToQueue("170301fffb");
+  auto longBuf = IOBuf::create(0xfffb);
+  longBuf->append(0xfffb);
+  queue_.append(std::move(longBuf));
+  EXPECT_FALSE(read_.read(queue_).hasValue());
+  EXPECT_TRUE(queue_.empty());
+}
+
 TEST_F(PlaintextRecordTest, TestWaitBeforeSkip) {
   read_.setSkipEncryptedRecords(true);
   addToQueue("170301000501234567");
```
