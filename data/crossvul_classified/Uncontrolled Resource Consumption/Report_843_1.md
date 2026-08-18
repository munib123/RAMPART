# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 843_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `843_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 163-203 of the vulnerable file.

TEST_F(EncryptedRecordTest, TestAllPaddingAppData) {
  addToQueue("17030100050123456789");
  EXPECT_CALL(*readAead_, _decrypt(_, _, 0))
      .WillOnce(Invoke([](std::unique_ptr<IOBuf>& buf, const IOBuf*, uint64_t) {
        expectSame(buf, "0123456789");
        return getBuf("17000000");
      }));
  auto msg = read_.read(queue_);
  EXPECT_EQ(msg->type, ContentType::application_data);
  EXPECT_TRUE(msg->fragment->empty());
  EXPECT_TRUE(queue_.empty());
}

TEST_F(EncryptedRecordTest, TestAllPaddingHandshake) {
  addToQueue("17030100050123456789");
  EXPECT_CALL(*readAead_, _decrypt(_, _, 0))
      .WillOnce(Invoke([](std::unique_ptr<IOBuf>& buf, const IOBuf*, uint64_t) {
        expectSame(buf, "0123456789");
        return getBuf("16000000");
      }));
  EXPECT_NO_THROW(read_.read(queue_));
}

TEST_F(EncryptedRecordTest, TestNoContentType) {
  addToQueue("17030100050123456789");
  EXPECT_CALL(*readAead_, _decrypt(_, _, 0))
      .WillOnce(Invoke([](std::unique_ptr<IOBuf>& buf, const IOBuf*, uint64_t) {
        expectSame(buf, "0123456789");
        return getBuf("00000000");
      }));
  EXPECT_ANY_THROW(read_.read(queue_));
}

TEST_F(EncryptedRecordTest, TestReadSeqNum) {
  for (int i = 0; i < 10; i++) {
    addToQueue("17030100050123456789");
    EXPECT_CALL(*readAead_, _decrypt(_, _, i))
        .WillOnce(
            Invoke([](std::unique_ptr<IOBuf>& buf, const IOBuf*, uint64_t) {
              expectSame(buf, "0123456789");
              return getBuf("1234abcd17");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -180,7 +180,7 @@
         expectSame(buf, "0123456789");
         return getBuf("16000000");
       }));
-  EXPECT_NO_THROW(read_.read(queue_));
+  EXPECT_ANY_THROW(read_.read(queue_));
 }
 
 TEST_F(EncryptedRecordTest, TestNoContentType) {
```
