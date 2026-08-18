# CrossVul Fix Pair: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) in java
**Pair ID:** 830_0
**Vulnerability Class:** Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
**CWE:** CWE-338
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `830_0`)

## Vulnerability Information & PoC

## Description
Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - When a non-cryptographic PRNG is used in a cryptographic context, it can expose the cryptography to certain types of attacks.

## Vulnerable Code
```java
Lines 177-217 of the vulnerable file.

    binder.bind(LOCAL_MEMORY_SESSION_CACHE_BINDING_KEY).toProvider(() -> {
      CacheBuilder<AsciiString, ByteBuf> cacheBuilder = Types.cast(CacheBuilder.newBuilder());
      cacheBuilder.removalListener(n -> n.getValue().release());
      config.accept(cacheBuilder);
      return cacheBuilder.build();
    }).in(Scopes.SINGLETON);
  }

  @Override
  protected void configure() {
    memoryStore(binder(), s -> s.maximumSize(1000));
  }

  @Provides
  @Singleton
  SessionStore sessionStoreAdapter(@Named(LOCAL_MEMORY_SESSION_CACHE_BINDING_NAME) Cache<AsciiString, ByteBuf> cache) {
    return new LocalMemorySessionStore(cache);
  }

  @Provides
  SessionIdGenerator sessionIdGenerator() {
    return new DefaultSessionIdGenerator();
  }

  @Provides
  @RequestScoped
  SessionId sessionId(Request request, Response response, SessionIdGenerator idGenerator, SessionCookieConfig cookieConfig) {
    return new CookieBasedSessionId(request, response, idGenerator, cookieConfig);
  }

  @Provides
  SessionSerializer sessionValueSerializer(JavaSessionSerializer sessionSerializer) {
    return sessionSerializer;
  }

  @Provides
  JavaSessionSerializer javaSessionSerializer() {
    return new JavaBuiltinSessionSerializer();
  }

  @Provides
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,6 +194,7 @@
   }
 
   @Provides
+  @Singleton
   SessionIdGenerator sessionIdGenerator() {
     return new DefaultSessionIdGenerator();
   }
```
