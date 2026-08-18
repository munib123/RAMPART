# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 597_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `597_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 1332-1372 of the vulnerable file.

  if (!getHTTP2PrioritiesEnabled()) {
    return;
  }
  http2::PriorityUpdate h2Pri{std::get<0>(pri), std::get<1>(pri),
      std::get<2>(pri)};
  HTTPTransaction* txn = findTransaction(streamID);
  if (txn) {
    // existing txn, change pri
    txn->onPriorityUpdate(h2Pri);
  } else {
    // virtual node
    txnEgressQueue_.addOrUpdatePriorityNode(streamID, h2Pri);
  }
}

void HTTPSession::onCertificateRequest(uint16_t requestId,
                                       std::unique_ptr<IOBuf> authRequest) {
  DestructorGuard dg(this);
  VLOG(4) << "CERTIFICATE_REQUEST on" << *this << ", requestId=" << requestId;

  std::pair<uint16_t, std::unique_ptr<folly::IOBuf>> authenticator;
  auto fizzBase = getTransport()->getUnderlyingTransport<AsyncFizzBase>();
  if (fizzBase) {
    if (isUpstream()) {
      authenticator =
          secondAuthManager_->getAuthenticator(*fizzBase,
                                               TransportDirection::UPSTREAM,
                                               requestId,
                                               std::move(authRequest));
    } else {
      authenticator =
          secondAuthManager_->getAuthenticator(*fizzBase,
                                               TransportDirection::DOWNSTREAM,
                                               requestId,
                                               std::move(authRequest));
    }
  } else {
    VLOG(4) << "Underlying transport does not support secondary "
               "authentication.";
    return;
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1349,6 +1349,10 @@
   DestructorGuard dg(this);
   VLOG(4) << "CERTIFICATE_REQUEST on" << *this << ", requestId=" << requestId;
 
+  if (!secondAuthManager_) {
+    return;
+  }
+
   std::pair<uint16_t, std::unique_ptr<folly::IOBuf>> authenticator;
   auto fizzBase = getTransport()->getUnderlyingTransport<AsyncFizzBase>();
   if (fizzBase) {
@@ -1381,6 +1385,10 @@
                                 std::unique_ptr<IOBuf> authenticator) {
   DestructorGuard dg(this);
   VLOG(4) << "CERTIFICATE on" << *this << ", certId=" << certId;
+
+  if (!secondAuthManager_) {
+    return;
+  }
 
   bool isValid = false;
   auto fizzBase = getTransport()->getUnderlyingTransport<AsyncFizzBase>();
```
