# CrossVul Fix Pair: Improper Certificate Validation in cpp
**Pair ID:** 4031_1
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4031_1`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```cpp
Lines 10-50 of the vulnerable file.

#include <pichi/api/balancer.hpp>
#include <pichi/api/vos.hpp>
#include <pichi/asserts.hpp>
#include <pichi/common.hpp>
#include <pichi/crypto/key.hpp>
#include <pichi/net/adapter.hpp>
#include <pichi/net/asio.hpp>
#include <pichi/net/common.hpp>
#include <pichi/net/direct.hpp>
#include <pichi/net/helpers.hpp>
#include <pichi/net/http.hpp>
#include <pichi/net/reject.hpp>
#include <pichi/net/socks5.hpp>
#include <pichi/net/ssaead.hpp>
#include <pichi/net/ssstream.hpp>
#include <pichi/net/tunnel.hpp>
#include <pichi/test/socket.hpp>

#ifdef ENABLE_TLS
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#endif // ENABLE_TLS

using namespace std;
namespace asio = boost::asio;
namespace ip = asio::ip;
namespace ssl = asio::ssl;
namespace sys = boost::system;
using ip::tcp;
using pichi::crypto::CryptoMethod;
using TcpSocket = tcp::socket;
using TlsSocket = ssl::stream<TcpSocket>;

namespace pichi::net {

#ifdef ENABLE_TLS
static auto createTlsContext(api::IngressVO const& vo)
{
  auto ctx = ssl::context{ssl::context::tls_server};
  ctx.use_certificate_chain_file(*vo.certFile_);
  ctx.use_private_key_file(*vo.keyFile_, ssl::context::pem);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,7 @@
 
 #ifdef ENABLE_TLS
 #include <boost/asio/ssl/context.hpp>
+#include <boost/asio/ssl/rfc2818_verification.hpp>
 #include <boost/asio/ssl/stream.hpp>
 #endif // ENABLE_TLS
 
@@ -56,11 +57,15 @@
   auto ctx = ssl::context{ssl::context::tls_client};
   if (*vo.insecure_) {
     ctx.set_verify_mode(ssl::context::verify_none);
-  }
+    return ctx;
+  }
+
+  ctx.set_verify_mode(ssl::context::verify_peer);
+  if (vo.caFile_.has_value())
+    ctx.load_verify_file(*vo.caFile_);
   else {
-    ctx.set_verify_mode(ssl::context::verify_peer);
     ctx.set_default_verify_paths();
-    if (vo.caFile_.has_value()) ctx.load_verify_file(*vo.caFile_);
+    ctx.set_verify_callback(ssl::rfc2818_verification{*vo.host_});
   }
   return ctx;
 }
```
