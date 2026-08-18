# CrossVul Fix Pair: Improper Authentication in cpp
**Pair ID:** 134_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```cpp
Lines 1-31 of the vulnerable file.

#include "CephxProtocol.h"
#include "CephxAuthorizeHandler.h"
#include "common/dout.h"

#define dout_subsys ceph_subsys_auth



bool CephxAuthorizeHandler::verify_authorizer(CephContext *cct, KeyStore *keys,
					      bufferlist& authorizer_data, bufferlist& authorizer_reply,
                                              EntityName& entity_name, uint64_t& global_id, AuthCapsInfo& caps_info, CryptoKey& session_key,  uint64_t *auid)
{
  bufferlist::iterator iter = authorizer_data.begin();

  if (!authorizer_data.length()) {
    ldout(cct, 1) << "verify authorizer, authorizer_data.length()=0" << dendl;
    return false;
  }

  CephXServiceTicketInfo auth_ticket_info;

  bool isvalid = cephx_verify_authorizer(cct, keys, iter, auth_ticket_info, authorizer_reply);

  if (isvalid) {
    caps_info = auth_ticket_info.ticket.caps;
    entity_name = auth_ticket_info.ticket.name;
    global_id = auth_ticket_info.ticket.global_id;
    session_key = auth_ticket_info.session_key;
    if (auid) *auid = auth_ticket_info.ticket.auid;
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,9 +6,12 @@
 
 
 
-bool CephxAuthorizeHandler::verify_authorizer(CephContext *cct, KeyStore *keys,
-					      bufferlist& authorizer_data, bufferlist& authorizer_reply,
-                                              EntityName& entity_name, uint64_t& global_id, AuthCapsInfo& caps_info, CryptoKey& session_key,  uint64_t *auid)
+bool CephxAuthorizeHandler::verify_authorizer(
+  CephContext *cct, KeyStore *keys,
+  bufferlist& authorizer_data, bufferlist& authorizer_reply,
+  EntityName& entity_name, uint64_t& global_id, AuthCapsInfo& caps_info,
+  CryptoKey& session_key, uint64_t *auid,
+  std::unique_ptr<AuthAuthorizerChallenge> *challenge)
 {
   bufferlist::iterator iter = authorizer_data.begin();
 
@@ -19,7 +22,8 @@
 
   CephXServiceTicketInfo auth_ticket_info;
 
-  bool isvalid = cephx_verify_authorizer(cct, keys, iter, auth_ticket_info, authorizer_reply);
+  bool isvalid = cephx_verify_authorizer(cct, keys, iter, auth_ticket_info, challenge,
+					 authorizer_reply);
 
   if (isvalid) {
     caps_info = auth_ticket_info.ticket.caps;
```
