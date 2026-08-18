# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 849_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `849_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 1433-1475 of the vulnerable file.

    return;
  }

  // Normal write
  AsyncSocket::handleWrite();
}

AsyncSocket::WriteResult AsyncSSLSocket::interpretSSLError(int rc, int error) {
  if (error == SSL_ERROR_WANT_READ) {
    // Even though we are attempting to write data, SSL_write() may
    // need to read data if renegotiation is being performed.  We currently
    // don't support this and just fail the write.
    LOG(ERROR) << "AsyncSSLSocket(fd=" << fd_ << ", state=" << int(state_)
               << ", sslState=" << sslState_ << ", events=" << eventFlags_
               << "): "
               << "unsupported SSL renegotiation during write";
    return WriteResult(
        WRITE_ERROR,
        std::make_unique<SSLException>(SSLError::INVALID_RENEGOTIATION));
  } else {
    if (zero_return(error, rc, errno)) {
      return WriteResult(0);
    }
    auto errError = ERR_get_error();
    VLOG(3) << "ERROR: AsyncSSLSocket(fd=" << fd_ << ", state=" << int(state_)
            << ", sslState=" << sslState_ << ", events=" << eventFlags_ << "): "
            << "SSL error: " << error << ", errno: " << errno
            << ", func: " << ERR_func_error_string(errError)
            << ", reason: " << ERR_reason_error_string(errError);
    return WriteResult(
        WRITE_ERROR,
        std::make_unique<SSLException>(error, errError, rc, errno));
  }
}

AsyncSocket::WriteResult AsyncSSLSocket::performWrite(
    const iovec* vec,
    uint32_t count,
    WriteFlags flags,
    uint32_t* countWritten,
    uint32_t* partialWritten) {
  if (sslState_ == STATE_UNENCRYPTED) {
    return AsyncSocket::performWrite(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1450,9 +1450,6 @@
         WRITE_ERROR,
         std::make_unique<SSLException>(SSLError::INVALID_RENEGOTIATION));
   } else {
-    if (zero_return(error, rc, errno)) {
-      return WriteResult(0);
-    }
     auto errError = ERR_get_error();
     VLOG(3) << "ERROR: AsyncSSLSocket(fd=" << fd_ << ", state=" << int(state_)
             << ", sslState=" << sslState_ << ", events=" << eventFlags_ << "): "
@@ -1589,10 +1586,7 @@
         *partialWritten = uint32_t(offset);
         return WriteResult(totalWritten);
       }
-      auto writeResult = interpretSSLError(int(bytes), error);
-      if (writeResult.writeReturn < 0) {
-        return writeResult;
-      } // else fall through to below to correctly record totalWritten
+      return interpretSSLError(int(bytes), error);
     }
 
     totalWritten += bytes;
```
