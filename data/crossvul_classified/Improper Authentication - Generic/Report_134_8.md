# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 134_8
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_8`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 6-32 of the vulnerable file.

 * Copyright (C) 2004-2009 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#ifndef CEPH_AUTHNONEAUTHORIZEHANDLER_H
#define CEPH_AUTHNONEAUTHORIZEHANDLER_H

#include "auth/AuthAuthorizeHandler.h"

class CephContext;

struct AuthNoneAuthorizeHandler : public AuthAuthorizeHandler {
  bool verify_authorizer(CephContext *cct, KeyStore *keys,
			 bufferlist& authorizer_data, bufferlist& authorizer_reply,
                         EntityName& entity_name, uint64_t& global_id,
			 AuthCapsInfo& caps_info, CryptoKey& session_key, uint64_t *auid=NULL) override;
  int authorizer_session_crypto() override;
};



#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,7 +23,8 @@
   bool verify_authorizer(CephContext *cct, KeyStore *keys,
 			 bufferlist& authorizer_data, bufferlist& authorizer_reply,
                          EntityName& entity_name, uint64_t& global_id,
-			 AuthCapsInfo& caps_info, CryptoKey& session_key, uint64_t *auid=NULL) override;
+			 AuthCapsInfo& caps_info, CryptoKey& session_key, uint64_t *auid,
+			 std::unique_ptr<AuthAuthorizerChallenge> *challenge) override;
   int authorizer_session_crypto() override;
 };
 
```
