# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 600_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `600_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 202-242 of the vulnerable file.


  void expectTransaction(HTTPTransaction** pTxn = nullptr) {
    EXPECT_CALL(*this, setTransaction(testing::_))
        .WillOnce(testing::SaveArg<0>(pTxn ? pTxn : &txn_));
  }

  void expectHeaders(std::function<void()> callback = std::function<void()>()) {
    if (callback) {
      EXPECT_CALL(*this, onHeadersComplete(testing::_))
          .WillOnce(testing::InvokeWithoutArgs(callback))
          .RetiresOnSaturation();
    } else {
      EXPECT_CALL(*this, onHeadersComplete(testing::_));
    }
  }

  void expectHeaders(std::function<void(std::shared_ptr<HTTPMessage>)> cb) {
    EXPECT_CALL(*this, onHeadersComplete(testing::_))
        .WillOnce(testing::Invoke(cb))
        .RetiresOnSaturation();
  }

  void expectTrailers(
      std::function<void(std::shared_ptr<HTTPHeaders> trailers)> cb) {
    EXPECT_CALL(*this, onTrailers(testing::_))
        .WillOnce(testing::Invoke(cb))
        .RetiresOnSaturation();
  }

  void expectChunkHeader(
      std::function<void()> callback = std::function<void()>()) {
    if (callback) {
      EXPECT_CALL(*this, onChunkHeader(testing::_))
          .WillOnce(testing::InvokeWithoutArgs(callback));
    } else {
      EXPECT_CALL(*this, onChunkHeader(testing::_));
    }
  }

  void expectBody(std::function<void()> callback = std::function<void()>()) {
    if (callback) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -219,6 +219,17 @@
     EXPECT_CALL(*this, onHeadersComplete(testing::_))
         .WillOnce(testing::Invoke(cb))
         .RetiresOnSaturation();
+  }
+
+  void expectTrailers(
+      std::function<void()> callback = std::function<void()>()) {
+    if (callback) {
+      EXPECT_CALL(*this, onTrailers(testing::_))
+          .WillOnce(testing::InvokeWithoutArgs(callback))
+          .RetiresOnSaturation();
+    } else {
+      EXPECT_CALL(*this, onTrailers(testing::_));
+    }
   }
 
   void expectTrailers(
```
