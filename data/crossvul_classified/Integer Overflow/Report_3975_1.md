# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3975_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3975_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.

}
}

/* Generic */
typedef struct _digest_nonce_data digest_nonce_data;
typedef struct _digest_nonce_h digest_nonce_h;

/* data to be encoded into the nonce's hex representation */
struct _digest_nonce_data {
    time_t creationtime;
    uint32_t randomdata;
};

/* the nonce structure we'll pass around */

struct _digest_nonce_h : public hash_link {
    digest_nonce_data noncedata;
    /* number of uses we've seen of this nonce */
    unsigned long nc;
    /* reference count */
    short references;
    /* the auth_user this nonce has been tied to */
    Auth::Digest::User *user;
    /* has this nonce been invalidated ? */

    struct {
        bool valid;
        bool incache;
    } flags;
};

void authDigestNonceUnlink(digest_nonce_h * nonce);
int authDigestNonceIsValid(digest_nonce_h * nonce, char nc[9]);
int authDigestNonceIsStale(digest_nonce_h * nonce);
const char *authenticateDigestNonceNonceHex(const digest_nonce_h * nonce);
int authDigestNonceLastRequest(digest_nonce_h * nonce);
void authenticateDigestNonceShutdown(void);
void authDigestNoncePurge(digest_nonce_h * nonce);
void authDigestUserLinkNonce(Auth::Digest::User * user, digest_nonce_h * nonce);
digest_nonce_h *authenticateDigestNonceNew(void);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,7 @@
     /* number of uses we've seen of this nonce */
     unsigned long nc;
     /* reference count */
-    short references;
+    uint64_t references;
     /* the auth_user this nonce has been tied to */
     Auth::Digest::User *user;
     /* has this nonce been invalidated ? */
```
