# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 134_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `134_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 119-159 of the vulnerable file.

    ::decode(created, bl);
    ::decode(expires, bl);
    ::decode(caps, bl);
    ::decode(flags, bl);
  }
};
WRITE_CLASS_ENCODER(AuthTicket)


/*
 * abstract authorizer class
 */
struct AuthAuthorizer {
  __u32 protocol;
  bufferlist bl;
  CryptoKey session_key;

  explicit AuthAuthorizer(__u32 p) : protocol(p) {}
  virtual ~AuthAuthorizer() {}
  virtual bool verify_reply(bufferlist::iterator& reply) = 0;
};


/*
 * Key management
 */ 
#define KEY_ROTATE_NUM 3   /* prev, current, next */

struct ExpiringCryptoKey {
  CryptoKey key;
  utime_t expiration;

  void encode(bufferlist& bl) const {
    __u8 struct_v = 1;
    ::encode(struct_v, bl);
    ::encode(key, bl);
    ::encode(expiration, bl);
  }
  void decode(bufferlist::iterator& bl) {
    __u8 struct_v;
    ::decode(struct_v, bl);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,6 +136,11 @@
   explicit AuthAuthorizer(__u32 p) : protocol(p) {}
   virtual ~AuthAuthorizer() {}
   virtual bool verify_reply(bufferlist::iterator& reply) = 0;
+  virtual bool add_challenge(CephContext *cct, bufferlist& challenge) = 0;
+};
+
+struct AuthAuthorizerChallenge {
+  virtual ~AuthAuthorizerChallenge() {}
 };
 
 
```
