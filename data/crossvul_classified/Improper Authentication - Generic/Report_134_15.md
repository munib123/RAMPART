# CrossVul Fix Pair: Improper Authentication in cpp
**Pair ID:** 134_15
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_15`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```cpp
Lines 124-170 of the vulnerable file.

    return r;
  }

  msgr->set_myname(entity_name_t::MGR(gid));
  msgr->set_addr_unknowns(client_addr);

  msgr->start();
  msgr->add_dispatcher_tail(this);

  started_at = ceph_clock_now();

  return 0;
}

entity_addr_t DaemonServer::get_myaddr() const
{
  return msgr->get_myaddr();
}


bool DaemonServer::ms_verify_authorizer(Connection *con,
    int peer_type,
    int protocol,
    ceph::bufferlist& authorizer_data,
    ceph::bufferlist& authorizer_reply,
    bool& is_valid,
    CryptoKey& session_key)
{
  AuthAuthorizeHandler *handler = nullptr;
  if (peer_type == CEPH_ENTITY_TYPE_OSD ||
      peer_type == CEPH_ENTITY_TYPE_MON ||
      peer_type == CEPH_ENTITY_TYPE_MDS ||
      peer_type == CEPH_ENTITY_TYPE_MGR) {
    handler = auth_cluster_registry.get_handler(protocol);
  } else {
    handler = auth_service_registry.get_handler(protocol);
  }
  if (!handler) {
    dout(0) << "No AuthAuthorizeHandler found for protocol " << protocol << dendl;
    is_valid = false;
    return true;
  }

  MgrSessionRef s(new MgrSession(cct));
  s->inst.addr = con->get_peer_addr();
  AuthCapsInfo caps_info;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,13 +141,15 @@
 }
 
 
-bool DaemonServer::ms_verify_authorizer(Connection *con,
-    int peer_type,
-    int protocol,
-    ceph::bufferlist& authorizer_data,
-    ceph::bufferlist& authorizer_reply,
-    bool& is_valid,
-    CryptoKey& session_key)
+bool DaemonServer::ms_verify_authorizer(
+  Connection *con,
+  int peer_type,
+  int protocol,
+  ceph::bufferlist& authorizer_data,
+  ceph::bufferlist& authorizer_reply,
+  bool& is_valid,
+  CryptoKey& session_key,
+  std::unique_ptr<AuthAuthorizerChallenge> *challenge)
 {
   AuthAuthorizeHandler *handler = nullptr;
   if (peer_type == CEPH_ENTITY_TYPE_OSD ||
@@ -175,7 +177,9 @@
       authorizer_data,
       authorizer_reply, s->entity_name,
       s->global_id, caps_info,
-      session_key);
+      session_key,
+      nullptr,
+      challenge);
   } else {
     dout(10) << __func__ << " no rotating_keys (yet), denied" << dendl;
     is_valid = false;
```
