# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 134_5
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_5`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 256-296 of the vulnerable file.

  uint64_t nonce_plus_one;
  void encode(bufferlist& bl) const {
    __u8 struct_v = 1;
    ::encode(struct_v, bl);
    ::encode(nonce_plus_one, bl);
  }
  void decode(bufferlist::iterator& bl) {
    __u8 struct_v;
    ::decode(struct_v, bl);
    ::decode(nonce_plus_one, bl);
  }
};
WRITE_CLASS_ENCODER(CephXAuthorizeReply)


struct CephXAuthorizer : public AuthAuthorizer {
private:
  CephContext *cct;
public:
  uint64_t nonce;

  explicit CephXAuthorizer(CephContext *cct_)
    : AuthAuthorizer(CEPH_AUTH_CEPHX), cct(cct_), nonce(0) {}

  bool build_authorizer();
  bool verify_reply(bufferlist::iterator& reply) override;
};



/*
 * TicketHandler
 */
struct CephXTicketHandler {
  uint32_t service_id;
  CryptoKey session_key;
  CephXTicketBlob ticket;        // opaque to us
  utime_t renew_after, expires;
  bool have_key_flag;

  CephXTicketHandler(CephContext *cct_, uint32_t service_id_)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -273,12 +273,14 @@
   CephContext *cct;
 public:
   uint64_t nonce;
+  bufferlist base_bl;
 
   explicit CephXAuthorizer(CephContext *cct_)
     : AuthAuthorizer(CEPH_AUTH_CEPHX), cct(cct_), nonce(0) {}
 
   bool build_authorizer();
   bool verify_reply(bufferlist::iterator& reply) override;
+  bool add_challenge(CephContext *cct, bufferlist& challenge) override;
 };
 
 
@@ -384,17 +386,41 @@
 };
 WRITE_CLASS_ENCODER(CephXServiceTicketInfo)
 
+struct CephXAuthorizeChallenge : public AuthAuthorizerChallenge {
+  uint64_t server_challenge;
+  void encode(bufferlist& bl) const {
+    __u8 struct_v = 1;
+    ::encode(struct_v, bl);
+    ::encode(server_challenge, bl);
+  }
+  void decode(bufferlist::iterator& bl) {
+    __u8 struct_v;
+    ::decode(struct_v, bl);
+    ::decode(server_challenge, bl);
+  }
+};
+WRITE_CLASS_ENCODER(CephXAuthorizeChallenge)
+
 struct CephXAuthorize {
   uint64_t nonce;
-  void encode(bufferlist& bl) const {
-    __u8 struct_v = 1;
+  bool have_challenge = false;
+  uint64_t server_challenge_plus_one = 0;
+  void encode(bufferlist& bl) const {
+    __u8 struct_v = 2;
     ::encode(struct_v, bl);
     ::encode(nonce, bl);
+    ::encode(have_challenge, bl);
+    ::encode(server_challenge_plus_one, bl);
   }
   void decode(bufferlist::iterator& bl) {
     __u8 struct_v;
     ::decode(struct_v, bl);
     ::decode(nonce, bl);
+    if (struct_v >= 2) {
+      ::decode(have_challenge, bl);
+      ::decode(server_challenge_plus_one, bl);
+    }
+
   }
 };
 WRITE_CLASS_ENCODER(CephXAuthorize)
@@ -409,9 +435,12 @@
 /*
  * Verify authorizer and generate reply authorizer
  */
-extern bool cephx_verify_authorizer(CephContext *cct, KeyStore *keys,
-				    bufferlist::iterator& indata,
-				    CephXServiceTicketInfo& ticket_info, bufferlist& reply_bl);
+extern bool cephx_verify_authorizer(
+  CephContext *cct, KeyStore *keys,
+  bufferlist::iterator& indata,
+  CephXServiceTicketInfo& ticket_info,
+  std::unique_ptr<AuthAuthorizerChallenge> *challenge,
+  bufferlist& reply_bl);
 
 
 
```
