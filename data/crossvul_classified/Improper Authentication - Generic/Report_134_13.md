# CrossVul Fix Pair: Improper Authentication in cpp
**Pair ID:** 134_13
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_13`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```cpp
Lines 1245-1285 of the vulnerable file.


  Session *session = static_cast<Session *>(con->get_priv());
  if (session) {
    if (session->is_closed()) {
      dout(3) << "ms_handle_remote_reset closing connection for session " << session->info.inst << dendl;
      con->mark_down();
      con->set_priv(NULL);
    }
    session->put();
  }
}

bool MDSDaemon::ms_handle_refused(Connection *con)
{
  // do nothing for now
  return false;
}

bool MDSDaemon::ms_verify_authorizer(Connection *con, int peer_type,
			       int protocol, bufferlist& authorizer_data, bufferlist& authorizer_reply,
			       bool& is_valid, CryptoKey& session_key)
{
  Mutex::Locker l(mds_lock);
  if (stopping) {
    return false;
  }
  if (beacon.get_want_state() == CEPH_MDS_STATE_DNE)
    return false;

  AuthAuthorizeHandler *authorize_handler = 0;
  switch (peer_type) {
  case CEPH_ENTITY_TYPE_MDS:
    authorize_handler = authorize_handler_cluster_registry->get_handler(protocol);
    break;
  default:
    authorize_handler = authorize_handler_service_registry->get_handler(protocol);
  }
  if (!authorize_handler) {
    dout(0) << "No AuthAuthorizeHandler found for protocol " << protocol << dendl;
    is_valid = false;
    return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1262,7 +1262,8 @@
 
 bool MDSDaemon::ms_verify_authorizer(Connection *con, int peer_type,
 			       int protocol, bufferlist& authorizer_data, bufferlist& authorizer_reply,
-			       bool& is_valid, CryptoKey& session_key)
+				     bool& is_valid, CryptoKey& session_key,
+				     std::unique_ptr<AuthAuthorizerChallenge> *challenge)
 {
   Mutex::Locker l(mds_lock);
   if (stopping) {
@@ -1294,7 +1295,7 @@
     is_valid = authorize_handler->verify_authorizer(
       cct, keys,
       authorizer_data, authorizer_reply, name, global_id, caps_info,
-      session_key);
+      session_key, nullptr, challenge);
   } else {
     dout(10) << __func__ << " no rotating_keys (yet), denied" << dendl;
     is_valid = false;
```
