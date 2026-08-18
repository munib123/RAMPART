# CrossVul Fix Pair: Improper Authentication in cpp
**Pair ID:** 134_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```cpp
Lines 287-327 of the vulnerable file.

  return true;
}

/*
 * PRINCIPAL: build authorizer to access the service.
 *
 * ticket, {timestamp}^session_key
 */
CephXAuthorizer *CephXTicketHandler::build_authorizer(uint64_t global_id) const
{
  CephXAuthorizer *a = new CephXAuthorizer(cct);
  a->session_key = session_key;
  a->nonce = ((uint64_t)rand() << 32) + rand();

  __u8 authorizer_v = 1;
  ::encode(authorizer_v, a->bl);
  ::encode(global_id, a->bl);
  ::encode(service_id, a->bl);

  ::encode(ticket, a->bl);

  CephXAuthorize msg;
  msg.nonce = a->nonce;

  std::string error;
  if (encode_encrypt(cct, msg, session_key, a->bl, error)) {
    ldout(cct, 0) << "failed to encrypt authorizer: " << error << dendl;
    delete a;
    return 0;
  }
  return a;
}

/*
 * PRINCIPAL: build authorizer to access the service.
 *
 * ticket, {timestamp}^session_key
 */
CephXAuthorizer *CephXTicketManager::build_authorizer(uint32_t service_id) const
{
  map<uint32_t, CephXTicketHandler>::const_iterator iter = tickets_map.find(service_id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -304,6 +304,7 @@
   ::encode(service_id, a->bl);
 
   ::encode(ticket, a->bl);
+  a->base_bl = a->bl;
 
   CephXAuthorize msg;
   msg.nonce = a->nonce;
@@ -390,7 +391,9 @@
  */
 bool cephx_verify_authorizer(CephContext *cct, KeyStore *keys,
 			     bufferlist::iterator& indata,
-			     CephXServiceTicketInfo& ticket_info, bufferlist& reply_bl)
+			     CephXServiceTicketInfo& ticket_info,
+			     std::unique_ptr<AuthAuthorizerChallenge> *challenge,
+			     bufferlist& reply_bl)
 {
   __u8 authorizer_v;
   uint32_t service_id;
@@ -455,6 +458,30 @@
     ldout(cct, 0) << "verify_authorizercould not decrypt authorize request with error: "
       << error << dendl;
     return false;
+  }
+
+  if (challenge) {
+    auto *c = static_cast<CephXAuthorizeChallenge*>(challenge->get());
+    if (!auth_msg.have_challenge || !c) {
+      c = new CephXAuthorizeChallenge;
+      challenge->reset(c);
+      get_random_bytes((char*)&c->server_challenge, sizeof(c->server_challenge));
+      ldout(cct,10) << __func__ << " adding server_challenge " << c->server_challenge
+		    << dendl;
+
+      encode_encrypt_enc_bl(cct, *c, ticket_info.session_key, reply_bl, error);
+      if (!error.empty()) {
+	ldout(cct, 10) << "verify_authorizer: encode_encrypt error: " << error << dendl;
+	return false;
+      }
+      return false;
+    }
+    ldout(cct, 10) << __func__ << " got server_challenge+1 "
+		   << auth_msg.server_challenge_plus_one
+		   << " expecting " << c->server_challenge + 1 << dendl;
+    if (c->server_challenge + 1 != auth_msg.server_challenge_plus_one) {
+      return false;
+    }
   }
 
   /*
@@ -493,3 +520,31 @@
   return true;
 }
 
+bool CephXAuthorizer::add_challenge(CephContext *cct, bufferlist& challenge)
+{
+  bl = base_bl;
+
+  CephXAuthorize msg;
+  msg.nonce = nonce;
+
+  auto p = challenge.begin();
+  if (!p.end()) {
+    std::string error;
+    CephXAuthorizeChallenge ch;
+    decode_decrypt_enc_bl(cct, ch, session_key, challenge, error);
+    if (!error.empty()) {
+      ldout(cct, 0) << "failed to decrypt challenge (" << challenge.length() << " bytes): "
+		    << error << dendl;
+      return false;
+    }
+    msg.have_challenge = true;
+    msg.server_challenge_plus_one = ch.server_challenge + 1;
+  }
+
+  std::string error;
+  if (encode_encrypt(cct, msg, session_key, bl, error)) {
+    ldout(cct, 0) << __func__ << " failed to encrypt authorizer: " << error << dendl;
+    return false;
+  }
+  return true;
+}
```
