# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 134_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 17-55 of the vulnerable file.


#include "Auth.h"
#include "AuthMethodList.h"
#include "include/types.h"
#include "common/Mutex.h"
// Different classes of session crypto handling

#define SESSION_CRYPTO_NONE 0
#define SESSION_SYMMETRIC_AUTHENTICATE 1
#define SESSION_SYMMETRIC_ENCRYPT 2

class CephContext;
class KeyRing;
class RotatingKeyRing;

struct AuthAuthorizeHandler {
  virtual ~AuthAuthorizeHandler() {}
  virtual bool verify_authorizer(CephContext *cct, KeyStore *keys,
				 bufferlist& authorizer_data, bufferlist& authorizer_reply,
                                 EntityName& entity_name, uint64_t& global_id,
				 AuthCapsInfo& caps_info, CryptoKey& session_key, uint64_t *auid = NULL) = 0;
  virtual int authorizer_session_crypto() = 0;
};

class AuthAuthorizeHandlerRegistry {
  Mutex m_lock;
  map<int,AuthAuthorizeHandler*> m_authorizers;
  AuthMethodList supported;

public:
  AuthAuthorizeHandlerRegistry(CephContext *cct_, std::string methods)
    : m_lock("AuthAuthorizeHandlerRegistry::m_lock"), supported(cct_, methods)
  {}
  ~AuthAuthorizeHandlerRegistry();
  
  AuthAuthorizeHandler *get_handler(int protocol);
};

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,9 @@
   virtual bool verify_authorizer(CephContext *cct, KeyStore *keys,
 				 bufferlist& authorizer_data, bufferlist& authorizer_reply,
                                  EntityName& entity_name, uint64_t& global_id,
-				 AuthCapsInfo& caps_info, CryptoKey& session_key, uint64_t *auid = NULL) = 0;
+				 AuthCapsInfo& caps_info, CryptoKey& session_key,
+				 uint64_t *auid,
+				 std::unique_ptr<AuthAuthorizerChallenge> *challenge) = 0;
   virtual int authorizer_session_crypto() = 0;
 };
 
```
