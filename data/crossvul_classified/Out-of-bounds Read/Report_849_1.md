# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 849_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `849_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 789-829 of the vulnerable file.

  HandshakeTimeoutCallback acceptCallback(&handshakeCallback);
  TestSSLServer server(&acceptCallback);

  // Set up SSL client
  EventBase eventBase;
  auto client =
      std::make_shared<SSLClient>(&eventBase, server.getAddress(), 1, 10);
  client->connect(true /* write before connect completes */);
  EventBaseAborter eba(&eventBase, 3000);
  eventBase.loop();

  usleep(100000);
  // This is checking that the connectError callback precedes any queued
  // writeError callbacks.  This matches AsyncSocket's behavior
  EXPECT_EQ(client->getWriteAfterConnectErrors(), 1);
  EXPECT_EQ(client->getErrors(), 1);
  EXPECT_EQ(client->getMiss(), 0);
  EXPECT_EQ(client->getHit(), 0);

  cerr << "SSLClientTimeoutTest test completed" << endl;
}

/**
 * Verify Client Ciphers obtained using SSL MSG Callback.
 */
TEST(AsyncSSLSocketTest, SSLParseClientHelloSuccess) {
  EventBase eventBase;
  auto clientCtx = std::make_shared<SSLContext>();
  auto serverCtx = std::make_shared<SSLContext>();
  serverCtx->setVerificationOption(SSLContext::SSLVerifyPeerEnum::VERIFY);
  serverCtx->ciphers("ECDHE-RSA-AES128-SHA:AES128-SHA:AES256-SHA");
  serverCtx->loadPrivateKey(kTestKey);
  serverCtx->loadCertificate(kTestCert);
  serverCtx->loadTrustedCertificates(kTestCA);
  serverCtx->loadClientCAList(kTestCA);

  clientCtx->setVerificationOption(SSLContext::SSLVerifyPeerEnum::VERIFY);
  clientCtx->ciphers("AES256-SHA:AES128-SHA");
  clientCtx->loadPrivateKey(kTestKey);
  clientCtx->loadCertificate(kTestCert);
  clientCtx->loadTrustedCertificates(kTestCA);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -806,6 +806,114 @@
   EXPECT_EQ(client->getHit(), 0);
 
   cerr << "SSLClientTimeoutTest test completed" << endl;
+}
+
+class PerLoopReadCallback : public AsyncTransportWrapper::ReadCallback {
+ public:
+  void getReadBuffer(void** bufReturn, size_t* lenReturn) override {
+    *bufReturn = buf_.data();
+    *lenReturn = buf_.size();
+  }
+
+  void readDataAvailable(size_t len) noexcept override {
+    VLOG(3) << "Read of size: " << len;
+    s_->setReadCB(nullptr);
+    s_->getEventBase()->runInLoop([this]() { s_->setReadCB(this); });
+  }
+
+  void readErr(const AsyncSocketException&) noexcept override {}
+
+  void readEOF() noexcept override {}
+
+  void setSocket(AsyncSocket* s) {
+    s_ = s;
+  }
+
+ private:
+  AsyncSocket* s_;
+  std::array<uint8_t, 1000> buf_;
+};
+
+class CloseNotifyConnector : public AsyncSocket::ConnectCallback {
+ public:
+  CloseNotifyConnector(EventBase* evb, const SocketAddress& addr) {
+    evb_ = evb;
+    ssl_ = AsyncSSLSocket::newSocket(std::make_shared<SSLContext>(), evb_);
+    ssl_->connect(this, addr);
+  }
+
+  void connectSuccess() noexcept override {
+    ssl_->writeChain(nullptr, IOBuf::copyBuffer("hi"));
+    auto ssl = const_cast<SSL*>(ssl_->getSSL());
+    SSL_shutdown(ssl);
+    auto fd = ssl_->detachNetworkSocket();
+    tcp_.reset(new AsyncSocket(evb_, fd), AsyncSocket::Destructor());
+    evb_->runAfterDelay(
+        [this]() {
+          perLoopReads_.setSocket(tcp_.get());
+          tcp_->setReadCB(&perLoopReads_);
+          evb_->runAfterDelay([this]() { tcp_->closeNow(); }, 10);
+        },
+        100);
+  }
+
+  void connectErr(const AsyncSocketException& ex) noexcept override {
+    FAIL() << ex.what();
+  }
+
+ private:
+  EventBase* evb_;
+  std::shared_ptr<AsyncSSLSocket> ssl_;
+  std::shared_ptr<AsyncSocket> tcp_;
+  PerLoopReadCallback perLoopReads_;
+};
+
+class ErrorCheckingWriteCallback : public AsyncSocket::WriteCallback {
+ public:
+  void writeSuccess() noexcept override {}
+
+  void writeErr(size_t, const AsyncSocketException& ex) noexcept override {
+    LOG(ERROR) << "write error: " << ex.what();
+    EXPECT_NE(
+        ex.getType(),
+        AsyncSocketException::AsyncSocketExceptionType::SSL_ERROR);
+  }
+};
+
+class WriteOnEofReadCallback : public ReadCallback {
+ public:
+  using ReadCallback::ReadCallback;
+
+  void readEOF() noexcept override {
+    LOG(INFO) << "Got EOF";
+    auto chain = IOBuf::create(0);
+    for (size_t i = 0; i < 1000 * 1000; i++) {
+      auto buf = IOBuf::create(10);
+      buf->append(10);
+      memset(buf->writableData(), 'x', 10);
+      chain->prependChain(std::move(buf));
+    }
+    socket_->writeChain(&writeCallback_, std::move(chain));
+  }
+
+  void readErr(const AsyncSocketException& ex) noexcept override {
+    LOG(ERROR) << ex.what();
+  }
+
+ private:
+  ErrorCheckingWriteCallback writeCallback_;
+};
+
+TEST(AsyncSSLSocketTest, EarlyCloseNotify) {
+  WriteOnEofReadCallback readCallback(nullptr);
+  HandshakeCallback handshakeCallback(&readCallback);
+  SSLServerAcceptCallback acceptCallback(&handshakeCallback);
+  TestSSLServer server(&acceptCallback);
+
+  EventBase eventBase;
+  CloseNotifyConnector cnc(&eventBase, server.getAddress());
+
+  eventBase.loop();
 }
 
 /**
```
