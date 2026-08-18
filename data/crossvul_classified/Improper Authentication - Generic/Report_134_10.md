# CrossVul Fix Pair: Improper Authentication in cpp
**Pair ID:** 134_10
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_10`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```cpp
Lines 1-32 of the vulnerable file.

// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2009-2011 New Dream Network
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "AuthUnknownAuthorizeHandler.h"

bool AuthUnknownAuthorizeHandler::verify_authorizer(CephContext *cct, KeyStore *keys,
						 bufferlist& authorizer_data, bufferlist& authorizer_reply,
						 EntityName& entity_name, uint64_t& global_id, AuthCapsInfo& caps_info, CryptoKey& session_key,
uint64_t *auid)
{
  // For unknown authorizers, there's nothing to verify.  They're "OK" by definition.  PLR

  return true;
}

// Return type of crypto used for this session's data;  for unknown, no crypt used

int AuthUnknownAuthorizeHandler::authorizer_session_crypto() 
{
  return SESSION_CRYPTO_NONE;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,10 +14,13 @@
 
 #include "AuthUnknownAuthorizeHandler.h"
 
-bool AuthUnknownAuthorizeHandler::verify_authorizer(CephContext *cct, KeyStore *keys,
-						 bufferlist& authorizer_data, bufferlist& authorizer_reply,
-						 EntityName& entity_name, uint64_t& global_id, AuthCapsInfo& caps_info, CryptoKey& session_key,
-uint64_t *auid)
+bool AuthUnknownAuthorizeHandler::verify_authorizer(
+  CephContext *cct, KeyStore *keys,
+  bufferlist& authorizer_data, bufferlist& authorizer_reply,
+  EntityName& entity_name, uint64_t& global_id, AuthCapsInfo& caps_info,
+  CryptoKey& session_key,
+  uint64_t *auid,
+  std::unique_ptr<AuthAuthorizerChallenge> *challenge)
 {
   // For unknown authorizers, there's nothing to verify.  They're "OK" by definition.  PLR
 
```
