# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 2264_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2264_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 135-175 of the vulnerable file.

///////////////////////////////////////////////////////////////////////////////
// hash context

class HashContext : public SweepableResourceData {
public:
  CLASSNAME_IS("Hash Context")
  // overriding ResourceData
  virtual const String& o_getClassNameHook() const { return classnameof(); }

  HashContext(HashEnginePtr ops_, void *context_, int options_)
    : ops(ops_), context(context_), options(options_), key(nullptr) {
  }

  explicit HashContext(const HashContext* ctx) {
    assert(ctx->ops);
    assert(ctx->ops->context_size >= 0);
    ops = ctx->ops;
    context = malloc(ops->context_size);
    ops->hash_copy(context, ctx->context);
    options = ctx->options;
    key = ctx->key ? strdup(ctx->key) : nullptr;
  }

  ~HashContext() {
    HashContext::sweep();
  }

  void sweep() FOLLY_OVERRIDE {
    /* Just in case the algo has internally allocated resources */
    if (context) {
      assert(ops->digest_size >= 0);
      unsigned char dummy[ops->digest_size];
      ops->hash_final(dummy, context);
      free(context);
    }

    free(key);
  }

  HashEnginePtr ops;
  void *context;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,7 +152,12 @@
     context = malloc(ops->context_size);
     ops->hash_copy(context, ctx->context);
     options = ctx->options;
-    key = ctx->key ? strdup(ctx->key) : nullptr;
+    if (ctx->key) {
+      key = static_cast<char*>(malloc(ops->block_size));
+      memcpy(key, ctx->key, ops->block_size);
+    } else {
+      key = nullptr;
+    }
   }
 
   ~HashContext() {
```
