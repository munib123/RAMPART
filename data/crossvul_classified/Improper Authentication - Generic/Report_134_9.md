# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 134_9
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_9`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 1-32 of the vulnerable file.

// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2009 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#ifndef CEPH_AUTHNONEPROTOCOL_H
#define CEPH_AUTHNONEPROTOCOL_H

#include "auth/Auth.h"

struct AuthNoneAuthorizer : public AuthAuthorizer {
  AuthNoneAuthorizer() : AuthAuthorizer(CEPH_AUTH_NONE) { }
  bool build_authorizer(const EntityName &ename, uint64_t global_id) {
    __u8 struct_v = 1;
    ::encode(struct_v, bl);
    ::encode(ename, bl);
    ::encode(global_id, bl);
    return 0;
  }
  bool verify_reply(bufferlist::iterator& reply) override { return true; }
};

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,8 @@
 
 #include "auth/Auth.h"
 
+class CephContext;
+
 struct AuthNoneAuthorizer : public AuthAuthorizer {
   AuthNoneAuthorizer() : AuthAuthorizer(CEPH_AUTH_NONE) { }
   bool build_authorizer(const EntityName &ename, uint64_t global_id) {
@@ -27,6 +29,7 @@
     return 0;
   }
   bool verify_reply(bufferlist::iterator& reply) override { return true; }
+  bool add_challenge(CephContext *cct, bufferlist& ch) override { return true; }
 };
 
 #endif
```
