# CrossVul Fix Pair: Improper Initialization in cpp
**Pair ID:** 4751_0
**Vulnerability Class:** Improper Initialization
**CWE:** CWE-665
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4751_0`)

## Vulnerability Information & PoC

## Description
Improper Initialization - This can have security implications when the associated resource is expected to have certain properties or values, such as a variable that determines whether a user has been authenticated or not.

## Vulnerable Code
```cpp
Lines 195-235 of the vulnerable file.


///////////////////////////////////////////////////////////////////////////////

void FastCGITransport::onBody(std::unique_ptr<folly::IOBuf> chain) {
  Lock lock(this);
  m_bodyQueue.append(std::move(chain));
  notify(); // wake-up the VM
}

void FastCGITransport::onBodyComplete() {
  Lock lock(this);
  m_bodyComplete = true;
  notify(); // wake-up the VM
}

void FastCGITransport::onHeader(std::unique_ptr<folly::IOBuf> key_chain,
                                std::unique_ptr<folly::IOBuf> value_chain) {
  Cursor keyCur(key_chain.get());
  auto key = keyCur.readFixedString(key_chain->computeChainDataLength());

  Cursor valCur(value_chain.get());
  auto value = valCur.readFixedString(value_chain->computeChainDataLength());

  m_requestParams[key] = value;
}

void FastCGITransport::onHeadersComplete() {
  m_scriptName   = getParamTyped<std::string>("SCRIPT_FILENAME");
  m_docRoot      = getParamTyped<std::string>("DOCUMENT_ROOT");
  m_pathTrans    = getParamTyped<std::string>("PATH_TRANSLATED");
  m_serverObject = getParamTyped<std::string>("SCRIPT_NAME");

  if (!m_docRoot.empty() && *m_docRoot.rbegin() != '/') {
    m_docRoot += '/';
  }

  if (m_scriptName.empty() || RuntimeOption::ServerFixPathInfo) {
    // According to php-fpm, some servers don't set SCRIPT_FILENAME. In
    // this case, it uses PATH_TRANSLATED.
    // Added runtime option to change m_scriptFilename to s_pathTran
    // which will allow mod_fastcgi and mod_action to work correctly.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -212,6 +212,10 @@
   Cursor keyCur(key_chain.get());
   auto key = keyCur.readFixedString(key_chain->computeChainDataLength());
 
+  // Don't allow requests to inject an HTTP_PROXY environment variable by
+  // sending a Proxy header.
+  if (strcasecmp(key.c_str(), "HTTP_PROXY") == 0) return;
+
   Cursor valCur(value_chain.get());
   auto value = valCur.readFixedString(value_chain->computeChainDataLength());
 
```
